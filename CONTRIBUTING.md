# Contributing to HPXNODE

Thanks for helping improve the HPXPANEL edge node.

## Questions

Use [HPXPANEL discussions/issues](https://github.com/pooyahpx/HPXPANEL/issues) or open an issue on this repo.

## Reporting bugs

Include:

- What you expected vs what happened
- Node logs (`hpx-node logs` or `docker compose logs`)
- Whether you used the one-liner installer or a manual compose
- Host OS and Docker version

Do not paste live API keys or private keys.

## Pull requests

1. Branch from `main` (or `dev` if present)
2. Keep changes focused
3. Run `make test` when possible
4. Describe the why in the PR body

## Project layout

```
backend/     # Xray, WireGuard, OpenVPN, IKEv2, L2TP
cmd/         # node entrypoint
controller/  # gRPC / REST control plane
config/      # env + settings
docker/      # container entrypoint
scripts/     # install.sh
```
