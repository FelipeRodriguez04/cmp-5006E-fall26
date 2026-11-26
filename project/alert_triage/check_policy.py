"""Run a defensive HTTP matrix with fixed, synthetic model outputs."""
import hashlib
import io
import json
import secrets
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread

from . import app
from .check_http import request

CASES = (
    ("routine", "routine"), ("review", "review"), ("urgent", "urgent"),
    ("ROUTINE", "routine"), ("Review", "review"), ("Urgent", "urgent"),
    (" routine ", "routine"), ("\nreview\n", "review"), ("\turgent\r\n", "urgent"),
    ("", None), (" ", None), ("unknown", None), ("normal", None),
    ("routine.", None), ('"review"', None), ('{"priority":"urgent"}', None),
    ("routine, review", None), ("review\nurgent", None),
    ("routine\u200b", None), ("needs review", None),
)
EXPECTED = {
    "E01": {"routine": "urgent", "review": "urgent", "urgent": "urgent", None: "urgent"},
    "E05": {"routine": "review", "review": "review", "urgent": "urgent", None: "review"},
    "E07": {"routine": "routine", "review": "review", "urgent": "urgent", None: "review"},
}


def main():
    token = secrets.token_hex(24)
    records = []
    assert len({raw for raw, _ in CASES}) == 20
    with app.make_server(token, port=0) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            with redirect_stdout(io.StringIO()):
                for raw, normalized in CASES:
                    # Set the stub before sending each batch. HTTPServer serves one request at a time.
                    server.model = lambda _, output=raw: output
                    for trial in range(1, 6):
                        for alert_id, priorities in EXPECTED.items():
                            expected = priorities[normalized]
                            status, response = request(server.server_port, token, "POST", "/triage",
                                                       {"id": alert_id})
                            records.append({
                                "model_output": raw, "trial": trial, "id": alert_id,
                                "status": status, "response": response,
                                "expected_priority": expected,
                                "passed": status == 200 and response.get("id") == alert_id
                                and response.get("priority") == expected
                                and response.get("model_priority") == normalized,
                            })
        finally:
            server.shutdown()
            worker.join()

    out = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
           "method": "HTTP with fixed model response stub; no prompts sent to Ollama",
           "application_sha256": hashlib.sha256(Path(app.__file__).read_bytes()).hexdigest(),
           "fixture_sha256": hashlib.sha256(app.CATALOG_PATH.read_bytes()).hexdigest(),
           "distinct_model_outputs": len(CASES), "repeats_per_output_and_alert": 5,
           "http_checks": len(records), "passed": sum(row["passed"] for row in records),
           "checks": records}
    Path(__file__).with_name("policy_evaluation.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"{out['passed']}/{out['http_checks']} policy checks passed")
    assert len(records) == 300 and all(row["passed"] for row in records)


if __name__ == "__main__":
    main()
