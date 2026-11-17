# python:3.13-slim (3.13.18 on Debian trixie), pinned by its multi-platform
# index digest so every build starts from the same image. To update, look up
# the new digest with: docker buildx imagetools inspect python:3.13-slim
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# System packages:
# - curl for the health check.
# - tshark for PCAP analysis (it reads uploaded files only; it never
#   captures). wireshark-common asks whether non-root users may capture;
#   answer no ahead of time so the install does not stop for input.
# prlimit, which puts resource limits on tshark, is already in the base
# image (util-linux).
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first, so a code change does not reinstall them. The image
# has no compiler on purpose: every requirement installs from a prebuilt
# wheel, and --only-binary makes a package that would need building fail
# the build instead of pulling in a toolchain.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt

# The app itself (.dockerignore keeps everything else out).
COPY . /app

# Copied files keep the build machine's permissions, so a checkout with
# private files (0600, or a 0700 directory) would leave the app user unable
# to read its own code or the ATT&CK data. Make the tree readable by all and
# leave it owned by root, so the app user can read it but not change it.
RUN chmod -R a+rX /app

# Run as an unprivileged user that owns nothing in /app.
RUN useradd --create-home --uid 10001 aegis
USER aegis

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
