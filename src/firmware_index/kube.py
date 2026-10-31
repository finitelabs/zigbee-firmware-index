"""Starting a publish run as a Job made from the CronJob, as `kubectl create job --from` does."""

import os
import ssl
from pathlib import Path

import aiohttp

ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def job_from(cronjob: dict, anyway: bool) -> dict:
    name = cronjob["metadata"]["name"]
    template = cronjob["spec"]["jobTemplate"]
    spec = template["spec"]
    if anyway:
        container = spec["template"]["spec"]["containers"][0]
        container["args"] = list(container.get("args") or ["publish"]) + ["--anyway"]
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "generateName": f"{name}-manual-",
            "labels": template.get("metadata", {}).get("labels", {}),
            "annotations": {"cronjob.kubernetes.io/instantiate": "manual"},
            "ownerReferences": [
                {
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "name": name,
                    "uid": cronjob["metadata"]["uid"],
                    "controller": True,
                }
            ],
        },
        "spec": spec,
    }


async def start_publish(anyway: bool) -> str:
    """Start a run; returns the new Job's name."""
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    if not host:
        raise RuntimeError("this page is not running in Kubernetes")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    cronjob = os.environ.get("PUBLISH_CRONJOB", "publish")
    namespace = (ACCOUNT / "namespace").read_text().strip()
    token = (ACCOUNT / "token").read_text().strip()
    context = ssl.create_default_context(cafile=str(ACCOUNT / "ca.crt"))
    base = f"https://{host}:{port}/apis/batch/v1/namespaces/{namespace}"
    headers = {"Authorization": f"Bearer {token}"}
    async with aiohttp.ClientSession(
        headers=headers, timeout=aiohttp.ClientTimeout(total=30)
    ) as session:
        async with session.get(
            f"{base}/cronjobs/{cronjob}", ssl=context, raise_for_status=True
        ) as r:
            body = job_from(await r.json(), anyway)
        async with session.post(f"{base}/jobs", json=body, ssl=context, raise_for_status=True) as r:
            return (await r.json())["metadata"]["name"]
