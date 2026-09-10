# S0 Bare-Metal Live ISO Builder Container
# Used for building s0-live-amd64.hybrid.iso from Windows (Docker Desktop), macOS, or Linux without host dependencies.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

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
COPY auto/build.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/workspace"]

ENTRYPOINT ["/bin/bash", "-c", "cd /workspace/linux/iso && ./build.sh && cp live-image-amd64.hybrid.iso /workspace/s0-live-amd64.hybrid.iso 2>/dev/null || true"]
