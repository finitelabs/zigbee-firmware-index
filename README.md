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
| `publish --local DIR`    | One run into the folder DIR/site, with its own database and key in DIR/data |
| `serve`                  | The admin page, which also publishes on its daily schedule and on Publish now (the image's default command) |
| `serve --local DIR`      | The same on 127.0.0.1 with no sign-in, publishing into DIR             |
| `dump`                   | Writes a consistent copy of the database to stdout, for backups       |
| `keygen PATH`            | Writes a new Ed25519 signing key to PATH and prints its public key    |
| `check URL`              | Checks the public site as a reader sees it; exits 1 on any problem    |

`serve` and `publish` read:

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

`serve` also reads:

| Variable          | What                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `ADMIN_EMAILS`    | Comma-separated emails allowed in                                    |
| `HOST`, `PORT`    | Where it listens (default `0.0.0.0:8080`)                            |

So the whole service is one container running `serve`, with the data volume
mounted, behind a reverse proxy that signs users in.

## The admin page

It sits behind a sign-in proxy that sets `X-Auth-Request-Email` and strips that
header from anything a client sends; the page lets in only the emails in
`ADMIN_EMAILS`. A form is accepted only from the page's own origin. `/healthz`
needs no sign-in.

- **Runs**: each run's report, Publish now and Publish anyway, and the schedule:
  one run a day at a set UTC time, on or off. A run missed while the app was
  down starts when it is back that day. One run at a time.
- **Sources**: priority, delay, on or off, and each source's config.
- **Images**: search the published index; hold, drop or correct one file, each
  by adding a rule.
- **Rules**: add, switch on or off, delete, and download as YAML.
- **Uploads**: a file or URL is checked and cut to its OTA image, then saved
  with any fields given; it goes out on the next run.
- **Audit**: who changed what, and when.

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

## The outside check

`check URL` reads `latest.json`, the snapshot it names and `signing-key.pub`. It
fails if the last good run is over 48 hours old, the snapshot's sha512 or the
signature does not match, or the snapshot is empty. With `SIGNING_KEY_PUB` set,
the site's key must be that key.

The Check the site workflow runs it every 6 hours from GitHub, once the
repository variable `OTA_CHECK_ENABLED` is `true`. It reads
the variables `PUBLIC_URL` and `SIGNING_KEY_PUB`, and posts a failure to the
secret `DISCORD_WEBHOOK_URL`. GitHub turns a schedule off after 60 days with no
activity in the repository.

## Run it locally

```bash
make dev
```

This serves the admin page at <http://127.0.0.1:8080/> with no sign-in, and keeps
everything under `.dev/`: the database and a signing key in `.dev/data`, and the
published site, on disk instead of R2, in `.dev/site`, served at
<http://127.0.0.1:8080/site/>. Publish now runs a real publish against the live
sources; the first takes about a minute to download every file.

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
