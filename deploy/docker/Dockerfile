FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY nexus ./nexus

RUN pip install --no-cache-dir -e .

RUN useradd -m -u 1000 nexus && chown -R nexus:nexus /app
USER nexus

ENTRYPOINT ["nexus"]
CMD ["--help"]
