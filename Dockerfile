FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk update && apk add --no-cache make curl bash sudo unzip

WORKDIR /src

COPY go* .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make NAME=main build
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
      xl2tpd ppp \
      wireguard-tools iptables nftables iproute2 kmod openssl curl ca-certificates procps && \
    rm -rf /var/lib/apt/lists/* /usr/sbin/policy-rc.d

# Fail the build if anything a backend shells out to at runtime is missing, so a
# broken image can never ship again. Each of these has already bitten us:
#   nft   - wireguard's host routing masquerades via nftables; without it the
#           tunnel handshakes but gets no egress (openvpn/ikev2 use iptables and
#           kept working, which made it look like a wireguard-only problem).
#   plugins - EAP-MSCHAPv2 needs openssl for MD4/DES, else every IKEv2 auth fails.
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
    XRAY_ASSETS_PATH=/usr/local/share/xray

WORKDIR /app
COPY --from=builder /src/main /app/main
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
