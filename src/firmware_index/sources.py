"""The sources a run reads, each turned into candidates: one per file and gate."""

import json
import posixpath
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import zigpy.ota.providers

INDEX = "index"
ZIGPY = "zigpy"
UPLOAD = "upload"

# Spec section 4: lower priority wins a clash; delay in days.
DEFAULTS = [
    {"name": "uploads", "type": UPLOAD, "config": {}, "priority": 1, "delay_days": 0},
    {
        "name": "zigpy-ota",
        "type": ZIGPY,
        "config": {"provider": "zigpy_ota", "channel": "stable"},
        "priority": 2,
        "delay_days": 0,
    },
    {
        "name": "community",
        "type": INDEX,
        "config": {"url": "https://raw.githubusercontent.com/Koenkk/zigbee-OTA/master/index.json"},
        "priority": 3,
        "delay_days": 0,
    },
    {
        "name": "ledvance",
        "type": ZIGPY,
        "config": {"provider": "ledvance"},
        "priority": 4,
        "delay_days": 7,
    },
    {
        "name": "sonoff",
        "type": ZIGPY,
        "config": {"provider": "sonoff"},
        "priority": 5,
        "delay_days": 7,
    },
    {
        "name": "ikea",
        "type": ZIGPY,
        "config": {"provider": "ikea"},
        "priority": 6,
        "delay_days": 7,
        "enabled": False,
    },
]


@dataclass
class Candidate:
    source: str
    priority: int
    url: str
    manufacturer: int
    image_type: int
    version: int
    file_name: str
    checksum: str | None = None
    model_id: str | None = None
    manufacturer_names: list[str] | None = None
    min_file_version: int | None = None
    max_file_version: int | None = None
    hardware_min: int | None = None
    hardware_max: int | None = None
    release_notes: str | None = None
    original_url: str | None = None
    # zigpy's metadata, which downloads with its provider's certificates and checks.
    meta: Any = field(default=None, repr=False, compare=False)

    def gate(self) -> tuple:
        return (
            self.manufacturer,
            self.image_type,
            self.version,
            self.model_id,
            tuple(self.manufacturer_names or ()),
            self.min_file_version,
            self.max_file_version,
            self.hardware_min,
            self.hardware_max,
        )

    def download_key(self) -> str:
        return f"{self.url}\n{self.checksum or ''}"

    def describe(self) -> str:
        model = f" {self.model_id}" if self.model_id else ""
        return (
            f"{self.source}: 0x{self.manufacturer:04X}/0x{self.image_type:04X}"
            f" v0x{self.version:08X}{model} ({self.file_name})"
        )

    def to_json(self) -> dict:
        # Not asdict: it deep-copies meta, and zigpy's metadata holds an SSL context.
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "meta"}

    @classmethod
    def from_json(cls, d: dict) -> "Candidate":
        return cls(**d)


SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.[A-Za-z0-9]+$")


def file_name(name_or_url: str, manufacturer: int, image_type: int, version: int) -> str:
    """A name safe in a URL path: the source's own where it is, else one from the identity."""
    name = posixpath.basename(urlparse(name_or_url).path)
    if SAFE_NAME.match(name):
        return name
    return f"{manufacturer:04X}-{image_type:04X}-{version:08X}.ota"


def from_index(source: str, priority: int, body: bytes) -> list[Candidate]:
    """Entries of an index in the community format."""
    out = []
    for e in json.loads(body):
        out.append(
            Candidate(
                source=source,
                priority=priority,
                url=e["url"],
                manufacturer=e["manufacturerCode"],
                image_type=e["imageType"],
                version=e["fileVersion"],
                file_name=file_name(
                    e.get("fileName") or e["url"],
                    e["manufacturerCode"],
                    e["imageType"],
                    e["fileVersion"],
                ),
                checksum=f"sha512:{e['sha512']}" if e.get("sha512") else None,
                model_id=e.get("modelId"),
                manufacturer_names=e.get("manufacturerName"),
                min_file_version=e.get("minFileVersion"),
                max_file_version=e.get("maxFileVersion"),
                hardware_min=e.get("hardwareVersionMin"),
                hardware_max=e.get("hardwareVersionMax"),
                release_notes=e.get("releaseNotes"),
                original_url=e.get("originalUrl") or e["url"],
            )
        )
    return out


def from_zigpy(source: str, priority: int, metas: list) -> list[Candidate]:
    """zigpy's metadata, one candidate per model it names (the community format has one)."""
    out = []
    for m in metas:
        if m.manufacturer_id is None or m.image_type is None:
            continue
        url = getattr(m, "url", None) or str(getattr(m, "path", ""))
        for model in m.model_names or (None,):
            out.append(
                Candidate(
                    source=source,
                    priority=priority,
                    url=url,
                    manufacturer=m.manufacturer_id,
                    image_type=m.image_type,
                    version=m.file_version,
                    file_name=file_name(url, m.manufacturer_id, m.image_type, m.file_version),
                    checksum=m.checksum,
                    model_id=model,
                    manufacturer_names=list(m.manufacturer_names) or None,
                    min_file_version=m.min_current_file_version,
                    max_file_version=m.max_current_file_version,
                    hardware_min=m.min_hardware_version,
                    hardware_max=m.max_hardware_version,
                    release_notes=m.release_notes or m.changelog,
                    original_url=url,
                    meta=m,
                )
            )
    return out


async def load_zigpy(config: dict) -> list:
    provider = zigpy.ota.providers.OTA_PROVIDER_TYPES[config["provider"]]
    kwargs = {"channel": config["channel"]} if "channel" in config else {}
    return await provider(**kwargs).load_index() or []


def from_uploads(source: str, priority: int, rows: list[dict], uploads: Path) -> list[Candidate]:
    out = []
    for r in rows:
        fields = json.loads(r["fields"])
        out.append(
            Candidate(
                source=source,
                priority=priority,
                url=(uploads / f"{r['sha512']}.ota").as_uri(),
                manufacturer=fields["manufacturer"],
                image_type=fields["image_type"],
                version=fields["version"],
                file_name=r["file_name"],
                checksum=f"sha512:{r['sha512']}",
                model_id=fields.get("model_id"),
                manufacturer_names=fields.get("manufacturer_names"),
                min_file_version=fields.get("min_file_version"),
                max_file_version=fields.get("max_file_version"),
                hardware_min=fields.get("hardware_min"),
                hardware_max=fields.get("hardware_max"),
                release_notes=fields.get("release_notes"),
                original_url=fields.get("original_url"),
            )
        )
    return out
