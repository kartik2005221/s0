# S0 Bare-Metal Live ISO Builder Container
# Used for building s0-live-amd64.hybrid.iso from Windows (Docker Desktop), macOS, or Linux without host dependencies.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    live-build \
    xorriso \
    squashfs-tools \
    debootstrap \
    isolinux \
    syslinux-common \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools \
    dosfstools \
    git \
    rsync \
    ca-certificates \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Entrypoint script that copies repo to ephemeral build dir, runs lb build, and outputs ISO
COPY container_build.sh /container_build.sh
RUN chmod +x /container_build.sh

VOLUME ["/workspace"]

ENTRYPOINT ["/container_build.sh"]
