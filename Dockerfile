FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py index.html ./

EXPOSE 3000
CMD ["python3", "server.py"]
