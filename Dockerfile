# STAGE 1: Fetch Pinned Binaries
FROM alpine:latest AS tool-fetcher
RUN apk add --no-cache curl
ENV SYFT_VERSION=v1.3.0
ENV GRYPE_VERSION=v0.80.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin ${SYFT_VERSION}
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin ${GRYPE_VERSION}

# STAGE 2: Main Sentinel Appliance
FROM python:3.14-slim

# 1. System Dependencies & Runtimes
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    maven \
    gradle \
    nodejs \
    npm \
    git \
    curl \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Copy Pinned Binaries
COPY --from=tool-fetcher /usr/local/bin/syft /usr/local/bin/syft
COPY --from=tool-fetcher /usr/local/bin/grype /usr/local/bin/grype

# 3. Create Non-Root User for Security (Least Privilege)
# This is a key 'National Interest' security feature
RUN groupadd -r sentinel_group && useradd -r -g sentinel_group -m sentinel_user

# 4. Install Pinned Python Helpers & Engines
RUN pip install --no-cache-dir setuptools==75.0.0 wheel==0.45.0 && \
    pip install --no-cache-dir \
    "ruamel.yaml==0.18.15" \
    "ruamel.yaml.clib==0.2.14" \
    semgrep==1.146.0 \
    detect-secrets==1.5.0

# 5. Application Setup
WORKDIR /app
COPY . /app

ENV PYTHONPATH="/app/src"
# Install in editable mode to link the 'sentinel' package in 'src'
# We use --break-system-packages if on a newer Debian, or simply pip install .
RUN pip install --no-cache-dir -e .

# Fix the Git ownership issue for the non-root user
RUN git config --global --add safe.directory /src_to_scan


# 6. Set Permissions for the Non-Root User
RUN chown -R sentinel_user:sentinel_group /app
USER sentinel_user

# 7. Healthcheck using your Orchestrator's internal logic
# Proves the appliance is 'Ready for Mission'
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sentara-build --check-only || exit 1
  