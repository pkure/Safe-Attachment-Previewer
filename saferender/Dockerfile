# hal-id: #HAL-20261110-0006-PK-R4
# Safe-render engine. Build needs the internet (packages + ClamAV signatures); RUN it with no network:
#   see scripts/preview-local.sh for the hardened `docker run` flags.
# Stage 1: Python deps. Compilers live only here (zxing-cpp has no wheel for every platform), never in the final image.
FROM debian:bookworm-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-dev g++ cmake make \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-dev.txt /app/
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt -r /app/requirements-dev.txt

# Stage 2: runtime.
FROM debian:bookworm-slim

ARG WITH_AV=1
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TMPDIR=/tmp \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates \
      libreoffice-writer-nogui libreoffice-calc-nogui libreoffice-impress-nogui \
      tesseract-ocr tesseract-ocr-eng fonts-dejavu-core fonts-liberation2 \
      $( [ "$WITH_AV" = 1 ] && echo clamav clamav-freshclam ) \
 && rm -rf /var/lib/apt/lists/*

# Signatures are baked in at build time: the container never reaches the internet at run time.
# Rebuild the image daily (CI) for fresh signatures.
RUN if [ "$WITH_AV" = 1 ]; then freshclam --stdout --no-warnings && rm -f /var/lib/clamav/freshclam.dat; fi

COPY --from=deps /opt/venv /opt/venv

COPY saferender /app/saferender
COPY tests /app/tests
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["python", "-m", "saferender.pipeline"]
