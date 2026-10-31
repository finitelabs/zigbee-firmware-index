"""Where a run publishes: the R2 bucket, or a folder for a dry run and tests."""

import uuid
from pathlib import Path
from typing import Protocol

IMMUTABLE = "public, max-age=31536000, immutable"
SHORT = "public, max-age=300"


class Store(Protocol):
    def exists(self, key: str) -> bool: ...

    def put(self, key: str, body: bytes, content_type: str, cache_control: str) -> None: ...


class DirStore:
    def __init__(self, root: Path):
        self.root = root

    def exists(self, key: str) -> bool:
        return (self.root / key).exists()

    def put(self, key: str, body: bytes, content_type: str, cache_control: str) -> None:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
        tmp.write_bytes(body)
        tmp.replace(path)


class R2Store:
    def __init__(self, endpoint: str, bucket: str, access_key_id: str, secret_access_key: str):
        import boto3
        from botocore.exceptions import ClientError

        self._missing = ClientError
        self.bucket = bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="auto",
        )

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except self._missing as e:
            if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return False
            raise
        return True

    def put(self, key: str, body: bytes, content_type: str, cache_control: str) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
            CacheControl=cache_control,
        )
