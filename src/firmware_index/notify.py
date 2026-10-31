"""Posting a run's alerts to Discord."""

import logging

import aiohttp

LOG = logging.getLogger(__name__)
LIMIT = 1900


def message(report) -> str | None:
    if not report.alerts:
        return None
    lines = [f"Firmware index run {report.started}: {report.status}"]
    lines += [f"- {a}" for a in report.alerts]
    if report.counts:
        lines.append(", ".join(f"{k} {v}" for k, v in report.counts.items()))
    text = "\n".join(lines)
    return text if len(text) <= LIMIT else text[: LIMIT - 3] + "..."


async def post(webhook: str | None, report) -> None:
    text = message(report)
    if not text or not webhook:
        return
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook, json={"content": text}, raise_for_status=True):
                pass
    except (aiohttp.ClientError, TimeoutError) as e:
        # aiohttp's total timeout raises TimeoutError, which is not a ClientError.
        LOG.error("could not post to Discord: %s", e)
