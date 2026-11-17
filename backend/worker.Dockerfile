FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/snake
RUN pip install --no-cache-dir "pydantic>=2.8,<3.0" "cryptography>=43.0,<47.0" \
    && groupadd --gid 10001 snake \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin snake

COPY app/__init__.py /opt/snake/app/__init__.py
COPY app/core/__init__.py /opt/snake/app/core/__init__.py
COPY app/core/worker_protocol.py /opt/snake/app/core/worker_protocol.py
COPY app/core/worker_signing.py /opt/snake/app/core/worker_signing.py
COPY worker_entrypoint.py /opt/snake/worker_entrypoint.py
COPY worker_https_server.py /opt/snake/worker_https_server.py

USER 10001:10001
ENTRYPOINT ["python", "/opt/snake/worker_entrypoint.py"]
