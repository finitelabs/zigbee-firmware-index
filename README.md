# Zigbee firmware index

The Finite Labs Zigbee OTA firmware index, published at
<https://ota.finitelabs.com/>.

Each `publish` run reads the upstream firmware indexes and vendor feeds, applies
our rules, adds the files we upload, checks every file, and publishes a static
index and copies of the files to Cloudflare R2. The index uses the community
Zigbee OTA index format, so any hub that takes an index URL can read it.

## Commands

The image's entry point is `python -m firmware_index`:

| Command                  | What it does                                                          |
| ------------------------ | --------------------------------------------------------------------- |
| `publish`                | One run. Exits 0 on success, 2 when the brake holds the index, 1 otherwise |
| `publish --anyway`       | One run that publishes even when the brake would hold the index       |
| `publish --dry-run DIR`  | One run into DIR/site, with its own database and key in DIR/data      |
| `keygen PATH`            | Writes a new Ed25519 signing key to PATH and prints its public key    |

`publish` reads:

| Variable                | What                                                       |
| ----------------------- | ---------------------------------------------------------- |
| `DATA_DIR`              | The data volume (default `/data`): the database and uploads |
| `SIGNING_KEY_PATH`      | The Ed25519 private key (PEM)                              |
| `R2_ENDPOINT`           | `https://<account id>.r2.cloudflarestorage.com`            |
| `R2_BUCKET`             | The bucket                                                 |
| `R2_ACCESS_KEY_ID`      | The bucket-scoped token's key id                           |
| `R2_SECRET_ACCESS_KEY`  | Its secret                                                 |
| `DISCORD_WEBHOOK_URL`   | Where a failure, a brake or a source's failure is posted (optional) |
| `PUBLIC_URL`            | The site's address (default `https://ota.finitelabs.com`)  |

## What a run does

1. Reads each enabled source. A source that fails, or suddenly lists nothing,
   keeps its last good list.
2. Leaves out entries younger than their source's delay.
3. Downloads each file not checked before and checks it against the source's
   checksum. Its OTA header must name the entry's manufacturer code, image type
   and file version. The published copy runs from the header through its total
   image size, without a vendor wrapper or trailing bytes.
4. Applies the rules: drop, hold, or set fields.
5. Merges: one entry per file and gate; when two sources list different files
   for one gate, the higher-priority source wins.
6. Stops if the index would lose more than 5% of its entries (the brake).
7. Uploads new files, a new snapshot if the index changed, then `index.json`
   and `latest.json`, which names the snapshot and carries an Ed25519 signature
   over `<snapshot path>\n<sha512>`.

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
