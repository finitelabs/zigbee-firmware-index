# Zigbee firmware index

The Finite Labs Zigbee OTA firmware index, published at
<https://ota.finitelabs.com/>.

## Commands

The image's entry point is `python -m firmware_index`:

| Command       | What it does                                                       |
| ------------- | ------------------------------------------------------------------ |
| `keygen PATH` | Writes a new Ed25519 signing key to PATH and prints its public key |

## Development

Work in a virtualenv:

```bash
python3.13 -m venv .venv
. .venv/bin/activate
make init install
make check test
```

- `make fmt` formats with black.
- Dependencies are `requirements.in` and `requirements-dev.in`. `make install`
  recompiles a changed one with pip-compile; `make install UPGRADE=1` upgrades
  them all.
- `make image` builds the image locally.
- `tools/github-setup` checks the repository's settings against the Finite Labs
  standard; `--apply` fixes any drift.

## Releases

A tag `vMAJOR.MINOR.PATCH` builds the image and pushes it to
`ghcr.io/finitelabs/zigbee-firmware-index` as the version, `MAJOR.MINOR` and
`MAJOR`, then publishes a GitHub release.

## License

AGPL-3.0.
