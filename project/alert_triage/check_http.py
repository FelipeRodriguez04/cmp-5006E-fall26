"""Check the defensive invariant and interface with fixed model outcomes."""
import http.client
import json
import secrets
from threading import Thread

from . import app


def request(port, token, method, path, payload=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None if payload is None else json.dumps(payload)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        assert response.getheader("Cache-Control") == "no-store"
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def main():
    def unavailable(_):
        raise ConnectionRefusedError("simulated Ollama outage")

    token = secrets.token_hex(24)
    with app.make_server(token, port=0, model=lambda _: "routine") as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        port = server.server_port
        try:
            assert request(port, None, "GET", "/queue")[0] == 401
            assert request(port, token, "POST", "/triage", {"id": "no-such-alert"})[0] == 404
            assert request(port, token, "POST", "/triage", {"id": "E01", "signal": "other"})[0] == 400
            status, row = request(port, token, "POST", "/triage", {"id": "E01"})
            assert status == 200 and row == {
                "id": "E01", "priority": "urgent", "mode": "sensor_floor",
                "model_priority": "routine",
            }
            status, row = request(port, token, "POST", "/triage", {"id": "E07"})
            assert status == 200 and row["priority"] == "routine"
            status, row = request(port, token, "POST", "/triage", {"id": "E05", "note": "Awaiting shift handover."})
            assert status == 200 and row["priority"] == "review"
            assert row["mode"] == "sensor_review_floor" and row["model_priority"] == "routine"
            assert request(port, token, "POST", "/triage", {"id": "E05", "sensor_review": False})[0] == 400
            assert request(port, token, "GET", "/queue")[1]["alerts"][0]["id"] == "E01"
        finally:
            server.shutdown()
            thread.join()
    critical, protected, regular = (app.load_cases()[index][0] for index in (0, 4, 6))
    for model in (unavailable, lambda _: "no valid label"):
        assert app.triage(critical, "", model)["priority"] == "urgent"
        assert app.triage(regular, "", model)["mode"] == "manual_fallback"
        assert app.triage(protected, "", model)["mode"] == "sensor_review_floor"
    assert app.triage(protected, "", lambda _: "urgent")["priority"] == "urgent"
    print("HTTP contract, queue order, sensor floor and fallback checks passed")


if __name__ == "__main__":
    main()
