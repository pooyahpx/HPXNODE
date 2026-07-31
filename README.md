# HPXNODE

Edge node for **[HPXPANEL](https://github.com/pooyahpx/HPXPANEL)** — multi-backend Docker deploy with Xray, WireGuard, OpenVPN, and IKEv2 / IPsec.

Docs: https://pooyahpx.github.io/HPXPANEL/

## One-click install (recommended)

```bash
sudo bash -c "$(curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh)" @ install
```

Interactive menu (toggle backends, set port / API key):

```bash
sudo bash -c "$(curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh)"
```

Non-interactive example:

```bash
sudo bash -c "$(curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh)" @ install -y \
  --service-port 62050 \
  --disable openvpn
```

After install, register the node in **HPXPANEL → Nodes** with the printed **Address**, **Node Port**, **API key**, and **Server CA**.

| Path | Purpose |
| --- | --- |
| `/opt/hpx-node` | Compose + installer |
| `/var/lib/hpx-node` | Certs + generated configs |
| `hpx-node status` / `logs` / `update` | Manage the node |

## Features

- **Xray** — VLESS / VMess / Trojan / Shadowsocks / REALITY
- **WireGuard** — kernel WG + host NAT
- **OpenVPN** — optional tunnel backend
- **IKEv2 / IPsec** — native strongSwan
- **Panel sync** — gRPC to HPXPANEL

## Docker Compose (manual)

```bash
mkdir -p /opt/hpx-node /var/lib/hpx-node
cd /opt/hpx-node
# edit docker-compose.yml — set API_KEY to a UUID
docker compose up -d
cat /var/lib/hpx-node/certs/ssl_cert.pem
```

Default image: `ghcr.io/pooyahpx/hpx-node:latest`  
If the image is not published yet, the installer falls back to building from this repository.

## Build from source

```bash
git clone https://github.com/pooyahpx/HPXNODE.git
cd HPXNODE
docker build -t hpx-node .
```

## Env flags

| Variable | Effect |
| --- | --- |
| `HPX_NODE_DISABLE_XRAY=1` | never run Xray on this node |
| `HPX_NODE_DISABLE_OPENVPN=1` | never run OpenVPN |
| `HPX_NODE_DISABLE_WIREGUARD=1` | never run WireGuard |
| `HPX_NODE_DISABLE_IKEV2=1` | never run IKEv2 |
| `HPX_NODE_WG_HOST_ROUTING=1` | enable host IPv4 forward + scoped NAT |

## License

See [LICENSE](LICENSE).
