FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY nexus ./nexus

RUN pip install --no-cache-dir -e .

# Non-root user
RUN useradd -m -u 1000 nexus && chown -R nexus:nexus /app
USER nexus

ENTRYPOINT ["nexus"]
CMD ["--help"]
