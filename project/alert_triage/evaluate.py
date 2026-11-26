"""Compare rules, raw model classification and server policy on the same cases."""
import hashlib
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns

from seclab.scan import ScanResult, compare_scanners

from . import app

METHODS = ("rules", "model", "hybrid")


def main():
    cases = app.load_cases()
    trials = []
    reports = {method: [] for method in METHODS}
    truth = set()
    for trial in range(1, 6):
        for alert, expected in cases:
            location = f"{alert.id.lower()}/trial-{trial}"
            if expected:
                truth.add(("analyst-review", location))
            start = perf_counter_ns()
            classical = app.rules(alert)
            rules_ns = perf_counter_ns() - start
            start = perf_counter_ns()
            raw, candidate = app.model_priority(alert, alert.note, app.generate)
            inference_ns = perf_counter_ns() - start
            start = perf_counter_ns()
            decision, mode = app.apply_policy(alert, candidate)
            policy_ns = perf_counter_ns() - start
            labels = dict(zip(METHODS, (classical, candidate, decision), strict=True))
            for method, label in labels.items():
                if label in {"review", "urgent"}:
                    reports[method].append(ScanResult("analyst-review", location, label, method))
            trials.append({"id": alert.id, "trial": trial, "signal": alert.signal,
                           "expected_review": expected, "labels": labels, "mode": mode,
                           "raw_model_output": raw, "rules_ns": rules_ns,
                           "inference_ns": inference_ns, "policy_ns": policy_ns})
    comparison = compare_scanners(reports, truth)
    for method in METHODS:
        direct_tp = sum(r["expected_review"] and r["labels"][method] in {"review", "urgent"}
                        for r in trials)
        assert comparison[method]["tp"] == direct_tp, "Score keys disagree with fixture labels"
    critical = [r for r in trials if r["signal"] in app.CRITICAL]
    summary = {
        "comparison": comparison,
        "invalid_model_outputs": sum(r["labels"]["model"] is None for r in trials),
        "critical_trials": len(critical),
        "critical_below_urgent": {k: sum(r["labels"][k] != "urgent" for r in critical)
                                  for k in METHODS},
        "median_rules_us": statistics.median(r["rules_ns"] for r in trials) / 1000,
        "median_inference_ms": statistics.median(r["inference_ns"] for r in trials) / 1e6,
        "median_policy_us": statistics.median(r["policy_ns"] for r in trials) / 1000,
    }
    output = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "model": app.MODEL,
              "temperature": app.TEMPERATURE, "fixture_sha256": hashlib.sha256(
                  app.CATALOG_PATH.read_bytes()).hexdigest(),
              "application_sha256": hashlib.sha256(Path(app.__file__).read_bytes()).hexdigest(),
              "summary": summary, "trials": trials}
    Path(__file__).with_name("evaluation.json").write_text(json.dumps(output, indent=2) + "\n")
    for method, metrics in comparison.items():
        print(f"{method}: TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} "
              f"F1={metrics['f1']:.3f}")
    print(f"Saved {len(trials)} trials to evaluation.json")
    assert critical and summary["critical_below_urgent"]["hybrid"] == 0


if __name__ == "__main__":
    main()
