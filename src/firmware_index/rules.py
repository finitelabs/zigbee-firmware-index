"""Rules: data that drops, holds or corrects an entry."""

import fnmatch
from dataclasses import dataclass, field

from firmware_index.sources import Candidate

DROP = "drop"
HOLD = "hold"
SET = "set"

MATCH_KEYS = {"sha512", "source", "manufacturerCode", "imageType", "fileVersion", "modelId", "url"}

# The fields a set rule may replace, by their names in the published index.
SETTABLE = {
    "modelId": "model_id",
    "manufacturerName": "manufacturer_names",
    "minFileVersion": "min_file_version",
    "maxFileVersion": "max_file_version",
    "hardwareVersionMin": "hardware_min",
    "hardwareVersionMax": "hardware_max",
    "releaseNotes": "release_notes",
    "otaHeaderString": "header_string",
}


@dataclass
class Rule:
    id: str
    action: str
    match: dict
    set: dict = field(default_factory=dict)
    note: str = ""
    enabled: bool = True

    def __post_init__(self):
        if self.action not in (DROP, HOLD, SET):
            raise ValueError(f"rule {self.id}: unknown action {self.action!r}")
        unknown = set(self.set) - set(SETTABLE)
        if unknown:
            raise ValueError(f"rule {self.id}: cannot set {', '.join(sorted(unknown))}")
        unknown = set(self.match) - MATCH_KEYS
        if unknown:
            raise ValueError(f"rule {self.id}: unknown match key {', '.join(sorted(unknown))}")

    def matches(self, c: Candidate, sha512: str | None, upstream_sha512: str | None) -> bool:
        for key, want in self.match.items():
            if key == "sha512":
                if want not in (sha512, upstream_sha512):
                    return False
            elif key == "source":
                if c.source != want:
                    return False
            elif key == "manufacturerCode":
                if c.manufacturer != want:
                    return False
            elif key == "imageType":
                if c.image_type != want:
                    return False
            elif key == "fileVersion":
                if isinstance(want, dict):
                    if c.version < want.get("min", 0) or c.version > want.get("max", 0xFFFFFFFF):
                        return False
                elif c.version != want:
                    return False
            elif key == "modelId":
                if c.model_id != want:
                    return False
            elif key == "url" and not fnmatch.fnmatchcase(c.url, want):
                return False
        return True


@dataclass
class Outcome:
    action: str | None
    applied: list[str]
    fields: dict


def apply(
    rules: list[Rule], c: Candidate, sha512: str | None, upstream_sha512: str | None
) -> Outcome:
    """Every enabled rule that matches. A drop beats a hold; set rules apply in order."""
    applied, fields, action = [], {}, None
    for r in rules:
        if not r.enabled or not r.matches(c, sha512, upstream_sha512):
            continue
        applied.append(r.id)
        if r.action == SET:
            fields.update(r.set)
        elif r.action == DROP or action is None:
            action = r.action
    return Outcome(action=action, applied=applied, fields=fields)
