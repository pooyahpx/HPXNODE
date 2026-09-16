# HPXNODE

Edge node for **[HPXPANEL](https://github.com/pooyahpx/HPXPANEL)** — multi-backend Docker deploy with Xray, WireGuard, OpenVPN, and IKEv2 / IPsec.

Docs: https://pooyahpx.github.io/HPXPANEL/

## One-click install (recommended)

Prompts **only Node Port + API Port**, then installs:

```bash
curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh -o /tmp/hpx-node.sh
sudo bash /tmp/hpx-node.sh install
```

Or one-liner:

```bash
sudo bash -c "$(curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/main/scripts/install.sh)" @ install
```

Full interactive menu (backends, image, instance name):

```bash
sudo bash /tmp/hpx-node.sh menu
```

Non-interactive custom ports:

```bash
sudo bash /tmp/hpx-node.sh install -y --service-port 63000 --api-port 63001 --api-key YOUR-UUID
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

After install, register the node in **HPXPANEL → Nodes** with the printed **Address**, **Node Port**, **API Port**, **API key**, and **Server CA**.

| Path | Purpose |
| --- | --- |
| `/opt/hpx-node` or `/opt/hpx-node-<name>` | Compose + installer |
| `/var/lib/hpx-node` or `/var/lib/hpx-node-<name>` | Certs + generated configs |
| `hpx-node list` / `status` / `logs` / `update` | Manage instances |

## Ports (important for the panel)

| Panel field | Default | What listens |
| --- | --- | --- |
| **Node Port** | `62050` | Node process (gRPC / CONNECTED status) |
| **API Port** | `62051` (Node Port + 1) | Management HTTPS — **Update Node**, core/geofile updates |

Both ports must be open in the firewall toward the panel. **CONNECTED** only proves Node Port works; **Update Node** needs API Port.

From **v0.6.2**, the management API runs **inside the node container** on `PANEL_API_PORT` (compose mounts `docker.sock`). Older installs (≤ 0.5.2 / early 0.6.0) do not have a reachable update API until you upgrade once on the host.

## Update Node (from host)

Upgrade image + refresh compose (adds docker.sock / in-container API):

```bash
sudo bash -c "$(curl -fsSL https://github.com/pooyahpx/HPXNODE/raw/v0.6.2/scripts/install.sh)" @ update -y
```

If the CLI is already installed:

```bash
sudo hpx-node update -y
# multi-instance:
sudo hpx-node --name shop1 update -y
```

Then open **API Port** in the firewall and **Reconnect** the node in HPXPANEL. `NODE VERSION` should become **0.6.2+**. After that, **Nodes → Update Node** in the panel works with one click (no SSH).

### Upgrading from 0.5.2

Panel **Update Node** cannot reach a 0.5.2 host by itself (no management API on API Port). You must run the host `update -y` command above **once** on each node, **or** configure panel SSH env (see HPXPANEL README) so the panel can run that command for you.

### “Node service is not reachable” / API Port errors

1. On the node: `sudo hpx-node update -y` (or the curl one-liner above) → get **≥ 0.6.2**
2. Firewall: allow **API Port** (and Node Port) from the panel
3. In the panel node form: **API Port** must match the host (`PANEL_API_PORT` / install prompt), not the Node Port
4. Reconnect the node, then try **Update Node** again

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
