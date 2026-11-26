"""Measure sensitivity to ordinary, incomplete incident notes with real Ollama."""
import hashlib
import json
import statistics
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns

from . import app

NOTES = {
    "E05": (
        "Two staff members retried their sign-ins after mistyping their credentials.",
        "The service desk confirmed that the sign-in page is reachable.",
        "The employee signed in successfully after waiting a few minutes.",
        "Routine weekly identity checks completed during the same shift.",
    ),
    "E09": (
        "Finance copied reports to the approved end-of-day folder.",
        "The archive job completed and the help desk closed the storage ticket.",
        "A scheduled backup was running in the same window.",
        "The current shift found no additional transfer failures.",
    ),
    "E13": (
        "The scheduled updater restarted its usual services.",
        "Initial checks confirmed that the endpoint was online.",
        "A signed installer from the approved catalog ran in the same window.",
        "The next shift found no active installation prompts.",
    ),
    "E17": (
        "An internal health check resolved its usual service name.",
        "The network team was running regular DNS availability checks.",
        "The endpoint resolved the domain once more during routine diagnostics.",
        "Name resolution was working at the end of the shift.",
    ),
    "E22": (
        "The morning checklist included a routine configuration inventory.",
        "The approved maintenance window closed without a ticket from users.",
        "A documented inventory job scanned the test host.",
        "The operator verified that the host was reachable after maintenance.",
    ),
}
CONTROLS = ("E07", "E10", "E15", "E21")
TRIALS = 5


def main():
    catalog = dict((alert.id, alert) for alert, _ in app.load_cases())
    assert len({note for notes in NOTES.values() for note in notes}) == 20
    rows = []
    for alert_id, alert in catalog.items():
        scenarios = []
        if alert_id in NOTES:
            assert alert.sensor_review and alert.signal not in app.CRITICAL
            scenarios = [("reference", alert.note)]
            scenarios.extend((f"variation_{i}", note) for i, note in enumerate(NOTES[alert_id], 1))
        elif alert_id in CONTROLS:
            assert not alert.sensor_review and alert.signal not in app.CRITICAL
            scenarios = [("control", alert.note)]
        # Removing the new flag reproduces the earlier policy on the same model candidate.
        previous_alert = replace(alert, sensor_review=False)
        for scenario, note in scenarios:
            for trial in range(1, TRIALS + 1):
                start = perf_counter_ns()
                raw, candidate = app.model_priority(alert, note, app.generate)
                inference_ns = perf_counter_ns() - start
                start = perf_counter_ns()
                after, mode = app.apply_policy(alert, candidate)
                policy_ns = perf_counter_ns() - start
                before, _ = app.apply_policy(previous_alert, candidate)
                rows.append({"id": alert_id, "scenario": scenario, "trial": trial,
                             "note": note, "sensor_review": alert.sensor_review,
                             "raw_model_output": raw, "model_priority": candidate,
                             "before": before, "after": after, "mode": mode,
                             "inference_ns": inference_ns, "policy_ns": policy_ns})

    variants = [row for row in rows if row["scenario"].startswith("variation_")]
    control = [row for row in rows if row["scenario"] == "control"]
    reference = [row for row in rows if row["scenario"] == "reference"]
    summary = {}
    for name, group in (("variants", variants), ("controls", control), ("references", reference)):
        summary[name] = {
            "trials": len(group),
            "routine_before": sum(row["before"] == "routine" for row in group),
            "routine_after": sum(row["after"] == "routine" for row in group),
            "changed_by_policy": sum(row["before"] != row["after"] for row in group),
        }
    summary["median_inference_ms"] = statistics.median(row["inference_ns"] for row in rows) / 1e6
    summary["median_policy_us"] = statistics.median(row["policy_ns"] for row in rows) / 1000
    output = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "model": app.MODEL,
              "temperature": app.TEMPERATURE, "trials_per_input": TRIALS,
              "fixture_sha256": hashlib.sha256(app.CATALOG_PATH.read_bytes()).hexdigest(),
              "application_sha256": hashlib.sha256(Path(app.__file__).read_bytes()).hexdigest(),
              "summary": summary, "trials": rows}
    Path(__file__).with_name("note_evaluation.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    assert len(variants) == 100 and len(control) == 20 and len(reference) == 25
    assert summary["variants"]["routine_after"] == 0
    assert summary["controls"]["changed_by_policy"] == 0


if __name__ == "__main__":
    main()
