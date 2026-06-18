import json
import pytest

from server.websocket import ConnectionManager


class FakeWS:
    def __init__(self):
        self.accepted = False
        self.sent = []
        self.closed = False

    async def accept(self):
        self.accepted = True

    async def send_text(self, payload):
        # normal send appends the payload
        self.sent.append(payload)

    async def close(self):
        self.closed = True


class FakeWSRaise(FakeWS):
    async def send_text(self, payload):
        raise RuntimeError("send failed")


@pytest.mark.asyncio
async def test_connect_and_send():
    mgr = ConnectionManager()
    ws = FakeWS()
    await mgr.connect("c1", ws)
    assert "c1" in mgr.active_connections

    await mgr.send_to_client("c1", {"a": 1})
    assert len(ws.sent) == 1
    assert json.loads(ws.sent[0]) == {"a": 1}

    # clean up
    await mgr.disconnect("c1")
    assert ws.closed is True
    assert "c1" not in mgr.active_connections


@pytest.mark.asyncio
async def test_send_error_triggers_disconnect():
    mgr = ConnectionManager()
    ws = FakeWSRaise()
    await mgr.connect("c2", ws)
    assert "c2" in mgr.active_connections

    # Sending will raise inside send_text and manager should disconnect the client
    await mgr.send_to_client("c2", "payload")
    assert ws.closed is True
    assert "c2" not in mgr.active_connections


@pytest.mark.asyncio
async def test_broadcast_removes_failed_clients():
    mgr = ConnectionManager()
    ws_ok = FakeWS()
    ws_bad = FakeWSRaise()

    await mgr.connect("good", ws_ok)
    await mgr.connect("bad", ws_bad)

    assert "good" in mgr.active_connections and "bad" in mgr.active_connections

    await mgr.broadcast({"hello": "world"})

    # good should have received the message
    assert len(ws_ok.sent) == 1
    assert json.loads(ws_ok.sent[0]) == {"hello": "world"}

    # bad should have been disconnected and closed
    assert ws_bad.closed is True
    assert "bad" not in mgr.active_connections
