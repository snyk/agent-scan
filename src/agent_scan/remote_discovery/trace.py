"""``--trace`` output: every call to the backend and its response, on stderr.

File contents and server configs can hold secrets, so they are replaced by sizes and
server names.
"""

import json
import sys
from typing import Any


def _request(body: dict[str, Any]) -> dict[str, Any]:
    if "results" not in body:
        return body
    results = []
    for result in body["results"]:
        result = dict(result)
        if "files" in result:
            result["files"] = [
                {"path": f["path"], "realpath": f["realpath"], "size": f["size"]} for f in result["files"]
            ]
        results.append(result)
    return {**body, "results": results}


def _mcp_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "client": entry["client"],
        "key": entry["key"],
        "candidates": [[sorted(m) for m in c["maps"]] for c in entry.get("candidates", [])],
        "fallback": entry["fallback"]["kind"],
        **({"skip_if_empty": True} if entry.get("skip_if_empty") else {}),
    }


def _response(body: dict[str, Any]) -> dict[str, Any]:
    found = body.get("found") or {}
    return {
        **body,
        "found": {
            "clients": found.get("clients", []),
            "mcp_configs": [_mcp_entry(e) for e in found.get("mcp_configs", [])],
            "skills_dirs": [
                {
                    "client": e["client"],
                    "key": e["key"],
                    "skills": [s["name"] for s in e["skills"]],
                }
                for e in found.get("skills_dirs", [])
            ],
        },
    }


def request(url: str, body: dict[str, Any], size: int) -> None:
    print(f"\n>>> POST {url} ({size} bytes)", file=sys.stderr)
    print(json.dumps(_request(body), indent=2), file=sys.stderr)


def response(status: int, body: dict[str, Any], elapsed_ms: float) -> None:
    print(f"<<< {status} ({elapsed_ms:.0f} ms)", file=sys.stderr)
    print(json.dumps(_response(body), indent=2), file=sys.stderr)
