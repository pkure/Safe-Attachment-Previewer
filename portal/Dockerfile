# hal-id: #HAL-20261113-0016-PK-D1
# Portal: Outlook add-in backend + signed-in viewer. Build from the repo root:
#   docker build -f portal/Dockerfile -t sap-portal .
# No secrets in the image; it proves its identity with the Container App's managed identity at run time.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VIEWER_DIR=/app/viewer
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
COPY portal/requirements.txt /app/portal/requirements.txt
RUN pip install --no-cache-dir -r /app/portal/requirements.txt
COPY viewer /app/viewer
COPY portal/app.py /app/portal/app.py
COPY portal/addin /app/portal/addin
COPY portal/static /app/portal/static
WORKDIR /app/portal
USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "180", "app:app"]
