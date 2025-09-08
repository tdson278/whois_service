# whois_service Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "uvicorn whois_flowise:app --host 0.0.0.0 --port ${PORT} --reload"]
