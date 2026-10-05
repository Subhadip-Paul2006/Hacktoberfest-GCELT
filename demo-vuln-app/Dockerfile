# NSAT Demo Vulnerable App — Dockerfile
# This file intentionally contains container misconfigurations for NSAT demo purposes.
# DO NOT use in production.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# NSAT-TARGET: Running as root (no USER instruction before this point)
USER root

# NSAT-TARGET: Docker socket mounted (container escape risk)
VOLUME ["/var/run/docker.sock"]

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "src.api.handlers:app", "--host", "0.0.0.0", "--port", "8000"]
