"""The outside check: what a reader of the public site sees, checked from anywhere."""

import datetime
import hashlib
import json

from firmware_index import keys

MAX_AGE = datetime.timedelta(hours=48)


async def problems(base: str, fetcher, now: datetime.datetime, pinned: str | None) -> list[str]:
    """Everything wrong with the site at base; empty when it is fine."""
    found = []
    try:
        latest = json.loads(await fetcher.get(f"{base}/latest.json"))
        public = (await fetcher.get(f"{base}/signing-key.pub")).decode().strip()
        snapshot = await fetcher.get(f"{base}/{latest['snapshot']}")
    except Exception as e:
        return [f"could not read the site: {type(e).__name__}: {e}"]

    checked = datetime.datetime.fromisoformat(latest["checked"])
    if now - checked > MAX_AGE:
        found.append(f"the last good run was at {latest['checked']}, over 48 hours ago")
    sha = hashlib.sha512(snapshot).hexdigest()
    if sha != latest["sha512"]:
        found.append(f"{latest['snapshot']} does not match the sha512 latest.json gives")
    if pinned and public != pinned:
        found.append("signing-key.pub is not the pinned public key")
    message = f"{latest['snapshot']}\n{latest['sha512']}".encode()
    if not keys.verify(pinned or public, message, latest["signature"]):
        found.append("latest.json's signature does not verify")
    try:
        if not json.loads(snapshot):
            found.append("the snapshot lists no entries")
    except json.JSONDecodeError:
        found.append("the snapshot is not JSON")
    return found
