FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk update && apk add --no-cache make curl bash sudo unzip

WORKDIR /src

COPY go* .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make NAME=main build
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build-serviced
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make install_xray

# Runtime is Debian (not Alpine) so the multi-backend fork's VPN deps —
# strongSwan/charon for IKEv2 and openvpn — match the packages the bare-metal
# installer uses and are known to work (EAP-MSCHAPv2 plugins included).
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/pooyahpx/HPXNODE"

# Don't let package postinst scripts try to start services during the build.
#
# NOTE: the strongswan crypto plugins are only *Recommends* of the strongswan
# package, so --no-install-recommends silently drops them and charon comes up
# with "plugin 'openssl': failed to load - no plugin file available". EAP-MSCHAPv2
# then fails for every user ("User authentication failed") no matter the password,
# because it can't compute the MD4/DES response. Pull the plugin packages in
# explicitly so IKEv2 actually works.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openvpn strongswan strongswan-swanctl \
      libcharon-extra-plugins libcharon-extauth-plugins \
      libstrongswan-standard-plugins libstrongswan-extra-plugins \
      xl2tpd ppp pptpd \
      ocserv openssh-server \
      wireguard-tools iptables nftables iproute2 kmod openssl curl ca-certificates procps && \
    rm -rf /var/lib/apt/lists/* /usr/sbin/policy-rc.d

# Optional runtime binaries: sing-box (anytls/tuic/naive sidecar) and mtg (MTProto).
# Failures here must not fail the image build — only the required tool check below is hard.
ARG TARGETARCH
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) sb_arch=amd64; mtg_arch=amd64 ;; \
      arm64) sb_arch=arm64; mtg_arch=arm64 ;; \
      *) sb_arch=amd64; mtg_arch=amd64 ;; \
    esac; \
    SINGBOX_VER=1.11.15; \
    curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-linux-${sb_arch}.tar.gz" \
      | tar -xz -C /tmp && \
      install -m 0755 /tmp/sing-box-${SINGBOX_VER}-linux-${sb_arch}/sing-box /usr/local/bin/sing-box && \
      rm -rf /tmp/sing-box-${SINGBOX_VER}-linux-${sb_arch} || \
      echo "WARN: sing-box download skipped/failed (optional)"; \
    MTG_VER=2.1.7; \
    curl -fsSL -o /tmp/mtg.tar.gz \
      "https://github.com/9seconds/mtg/releases/download/v${MTG_VER}/mtg-${MTG_VER}-linux-${mtg_arch}.tar.gz" && \
      tar -xzf /tmp/mtg.tar.gz -C /tmp && \
      install -m 0755 /tmp/mtg /usr/local/bin/mtg && \
      rm -rf /tmp/mtg /tmp/mtg.tar.gz || \
      echo "WARN: mtg download skipped/failed (optional)"

# Fail the build if anything a backend shells out to at runtime is missing, so a
# broken image can never ship again. Each of these has already bitten us:
#   nft   - wireguard's host routing masquerades via nftables; without it the
#           tunnel handshakes but gets no egress (openvpn/ikev2 use iptables and
#           kept working, which made it look like a wireguard-only problem).
#   plugins - EAP-MSCHAPv2 needs openssl for MD4/DES, else every IKEv2 auth fails.
# Optional backends (pptpd, ocserv, sshd, sing-box, mtg, awg) are installed when
# available above but are NOT required here.
RUN set -eux; \
    for b in nft iptables wg openvpn swanctl ip xl2tpd pppd; do \
      command -v "$b" >/dev/null || { echo "MISSING binary: $b" >&2; exit 1; }; \
    done; \
    plugins="$(ls /usr/lib/ipsec/plugins/ 2>/dev/null || true)"; \
    echo "$plugins"; \
    for p in openssl eap-mschapv2; do \
      echo "$plugins" | grep -q -- "$p" || { echo "MISSING strongswan plugin: $p" >&2; exit 1; }; \
    done

ENV SERVICE_PROTOCOL=grpc \
    NODE_HOST=0.0.0.0 \
    XRAY_EXECUTABLE_PATH=/usr/local/bin/xray \
    XRAY_ASSETS_PATH=/usr/local/share/xray \
    SINGBOX_EXECUTABLE_PATH=/usr/local/bin/sing-box \
    MTG_EXECUTABLE_PATH=/usr/local/bin/mtg

WORKDIR /app
COPY --from=builder /src/main /app/main
COPY --from=builder /src/hpx-node-serviced /usr/local/bin/hpx-node-serviced
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/hpx-node-cli.sh /usr/local/bin/hpx-node
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/hpx-node /usr/local/bin/hpx-node-serviced

# Docker CLI so in-container serviced can `docker compose pull/up` via mounted docker.sock.
ARG TARGETARCH
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) darch=x86_64; carch=x86_64 ;; \
      arm64) darch=aarch64; carch=aarch64 ;; \
      *) darch=x86_64; carch=x86_64 ;; \
    esac; \
    ver=27.5.1; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${darch}/docker-${ver}.tgz" \
      | tar -xz -C /tmp && \
      install -m 0755 /tmp/docker/docker /usr/local/bin/docker && \
      rm -rf /tmp/docker; \
    mkdir -p /usr/local/lib/docker/cli-plugins; \
    curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-${carch}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose && \
      chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
