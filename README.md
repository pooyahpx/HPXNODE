# HPXNODE

Edge node for **[HPXPANEL](https://github.com/pooyahpx/HPXPANEL)** — multi-backend Docker deploy with Xray, WireGuard, OpenVPN, and IKEv2 / IPsec.

Docs: https://pooyahpx.github.io/HPXPANEL/

## One-click install (recommended)

Save to a file first (safer than embedding the whole script in `bash -c`):

```bash
curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh -o /tmp/hpx-node.sh
sudo bash /tmp/hpx-node.sh install -y
```

Interactive menu (toggle backends, set port / API key / instance name):

```bash
curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh -o /tmp/hpx-node.sh
sudo bash /tmp/hpx-node.sh
```

Non-interactive example:

```bash
curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh -o /tmp/hpx-node.sh
sudo bash /tmp/hpx-node.sh install -y --service-port 62050 --disable openvpn
```

### Multiple nodes on one server (resale)

Each instance needs a unique **`--name`** and **`--service-port`** (panel Node Port). Register each in **HPXPANEL → Nodes**.

```bash
curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh -o /tmp/hpx-node.sh
sudo bash /tmp/hpx-node.sh install -y --name shop1 --service-port 62051
sudo bash /tmp/hpx-node.sh install -y --name shop2 --service-port 62052

sudo hpx-node list
sudo hpx-node --name shop1 status
```

Paths: `/opt/hpx-node-shop1`, `/var/lib/hpx-node-shop1`, …  
Also give each panel node **different VPN/inbound ports** (host networking — ports cannot collide).

After install, register the node in **HPXPANEL → Nodes** with the printed **Address**, **Node Port**, **API key**, and **Server CA**.

| Path | Purpose |
| --- | --- |
| `/opt/hpx-node` or `/opt/hpx-node-<name>` | Compose + installer |
| `/var/lib/hpx-node` or `/var/lib/hpx-node-<name>` | Certs + generated configs |
| `hpx-node list` / `status` / `logs` / `update` | Manage instances |

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
