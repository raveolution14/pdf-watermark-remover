# Use official Playwright Python image — browsers already installed, no sudo needed
FROM mcr.microsoft.com/playwright/python:v1.58.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "gunicorn rpp_app:app --bind 0.0.0.0:${PORT:-10000} --timeout 300 --workers 1"]
