"""The landing page at the root of the public site."""

from html import escape

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zigbee firmware index</title>
<style>
:root {{ color-scheme: light dark; --fg: #1d1d1f; --bg: #fff; --muted: #6e6e73; }}
@media (prefers-color-scheme: dark) {{ :root {{ --fg: #f5f5f7; --bg: #111; --muted: #a1a1a6; }} }}
body {{ font: 16px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg);
  max-width: 44rem; margin: 3rem auto; padding: 0 1rem; }}
code {{ font-size: 0.9em; word-break: break-all; }}
.muted {{ color: var(--muted); }}
</style>
</head>
<body>
<h1>Zigbee firmware index</h1>
<p>Over-the-air firmware files for Zigbee devices, from {manufacturers} manufacturers:
{count} files in all. Run by Finite Labs.</p>
<h2>Use it</h2>
<p>Point a Zigbee hub that reads an OTA index in the community Zigbee OTA index format at
<code>{base}/index.json</code>.</p>
<p>Each file is our copy, cut to the OTA image itself, with its SHA-512. Where a file
came from another site, <code>originalUrl</code> names it.</p>
<h2>Files</h2>
<ul>
<li><a href="index.json">index.json</a>: the current index</li>
<li><a href="latest.json">latest.json</a>: the current snapshot and its Ed25519 signature</li>
<li><a href="signing-key.pub">signing-key.pub</a>: the public key, <code>{public}</code></li>
</ul>
<p class="muted">Last checked {checked}. Current snapshot: <code>{snapshot}</code>.</p>
</body>
</html>
"""


def render(entries: list[dict], snapshot: str, checked: str, public: str, base: str) -> str:
    return PAGE.format(
        count=len({e["sha512"] for e in entries}),
        manufacturers=len({e["manufacturerCode"] for e in entries}),
        base=escape(base),
        public=escape(public),
        checked=escape(checked),
        snapshot=escape(snapshot),
    )
