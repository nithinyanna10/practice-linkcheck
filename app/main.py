from collections.abc import Iterator
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from app.chain import follow_chain
from app.rules import evaluate
from app.ssrf import is_blocked

app = FastAPI()


def get_client() -> Iterator[httpx.Client]:
    # follow_redirects must stay False: follow_chain checks every hop itself.
    with httpx.Client(follow_redirects=False) as client:
        yield client


class CheckRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def _http_url_with_host(cls, value: str) -> str:
        try:
            parts = urlsplit(value)
            valid = parts.scheme in ("http", "https") and bool(parts.hostname)
        except ValueError:  # e.g. "http://[::1/"
            valid = False
        if not valid:
            raise ValueError("url must be http(s) with a hostname")
        return value


@app.post("/links/check")
def check(body: CheckRequest, client: httpx.Client = Depends(get_client)) -> dict:
    if is_blocked(body.url):
        raise HTTPException(status_code=422, detail="url points to a blocked address")
    result = follow_chain(body.url, client)
    reasons = evaluate(result.chain, result.problem)
    return {
        "verdict": "suspicious" if reasons else "safe",
        "chain": result.chain,
        "reasons": reasons,
    }
