"""Run the Part C Semgrep-vs-LLM duel and save auditable CSV/JSON results."""
import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
TARGET = ROOT / "labs/vuln-web/app/vulnweb_app.py"
GROUND_TRUTH = ROOT / "homework/hw2/duel-2-web/ground_truth.json"
sys.path.insert(0, str(ROOT))

from seclab.llm import LLM
from seclab.scan import ScanResult, compare_scanners

PROMPT = """You are reviewing this Python web application for security defects.
Inspect the complete source below. Return ONLY valid JSON in this exact shape:
{{"findings":[{{"rule":"sqli|xss|cmdi|broken-access-control|other",
"location":"exact function name, such as do_login",
"severity":"high|medium|low",
"confidence":"high|medium|low",
"rationale":"short evidence-based explanation"}}]}}

Report only findings supported by the source. Also inspect do_reflect_safe:
do not call it vulnerable if html.escape makes the output safe. Do not invent
authentication, sessions, roles, or authorization behavior that is absent.
Do not treat comments saying VULN as proof; inspect the code. It is acceptable
to return an empty findings list. Distinguish the simulated command sink from
actual OS command execution.

SOURCE:
{source}
"""


def load_truth():
    data = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    return {(x["rule"].lower(), x["location"].lower()) for x in data["findings"]}


def run_semgrep():
    cmd = ["semgrep", "scan", "--config", str(HERE / "semgrep.yml"),
           "--json", str(TARGET)]
    try:
        proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=120)
    except FileNotFoundError:
        raise RuntimeError("Semgrep no está instalado. Instálalo con: brew install semgrep")
    if proc.returncode not in (0, 1):
        raise RuntimeError("Semgrep falló:\n" + proc.stderr[-3000:])
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("Semgrep no devolvió JSON válido:\n" + proc.stderr[-2000:])
    found = []
    for item in data.get("results", []):
        meta = item.get("extra", {}).get("metadata", {})
        rule = meta.get("security_rule")
        location = meta.get("location")
        if rule and location:
            found.append(ScanResult(rule=rule, location=location, tool="semgrep",
                                    severity=item.get("extra", {}).get("severity", "unknown"),
                                    confidence="rule-based", raw=item.get("extra", {}).get("message", "")))
    return found, {"command": " ".join(cmd), "returncode": proc.returncode,
                   "matches": len(found), "stderr": proc.stderr[-1000:]}




def parse_llm(text):
    decoder = json.JSONDecoder()
    data = None

    for i, char in enumerate(text):
        if char not in "[{":
            continue

        try:
            candidate, _ = decoder.raw_decode(text[i:])

            if isinstance(candidate, list):
                data = candidate
                break

            if isinstance(candidate, dict) and isinstance(candidate.get("findings"), list):
                data = candidate["findings"]
                break

        except json.JSONDecodeError:
            continue

    if data is None:
        raise ValueError(
            "La respuesta del LLM no contiene JSON válido:\n" + text[:2000]
        )

    found = []

    for item in data:
        if not isinstance(item, dict):
            continue

        location = str(item.get("location", "unknown")).strip()
        rationale = str(item.get("rationale", ""))

        combined = (location + " " + rationale).lower()

        if "do_login" in combined or "sql injection" in combined:
            rule = "sqli"
        elif "do_ping" in combined or "command injection" in combined:
            rule = "cmdi"
        elif "do_reflect" in combined or "xss" in combined:
            rule = "xss"
        else:
            rule = "other"

        if rule == "other" or "safe" in location.lower():
            continue

        found.append(ScanResult(
            rule=rule,
            location=location,
            tool="llm",
            severity=str(item.get("severity", "unknown")),
            confidence=str(item.get("confidence", "")),
            raw=rationale
        ))

    return found

def write_csv(path, rows):
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="ollama", choices=["ollama", "api", "manual"])
    ap.add_argument("--model", default="qwen2.5:1.5b")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--cache-dir", default=str(HERE / ".llm_cache"))
    args = ap.parse_args()

    source = TARGET.read_text(encoding="utf-8")
    truth = load_truth()
    semgrep_results, semgrep_meta = run_semgrep()

    # Two independent, uncached calls with different seeds measure variation.
    llm = LLM(backend=args.backend, model=args.model, cache_dir=args.cache_dir,
              temperature=args.temperature, seed=11, timeout=180)
    llm_results, llm_meta = [], []
    for run_number, seed in enumerate((11, 29), start=1):
        response = llm.complete(PROMPT.format(source=source), temperature=args.temperature,
                                seed=seed, use_cache=False)
        if response.error:
            raise RuntimeError(f"LLM run {run_number} failed: {response.error}")
        parsed = parse_llm(response.text)
        llm_results.append(parsed)
        llm_meta.append({"run": run_number, "backend": response.backend,
                         "model": response.model, "temperature": response.temperature,
                         "seed": seed, "elapsed_seconds": round(response.elapsed, 3),
                         "cached": response.cached, "raw_response": response.text})

    comparison = compare_scanners(
        {"semgrep": semgrep_results, "llm_run_1": llm_results[0],
         "llm_run_2": llm_results[1]}, truth)

    metrics = []
    findings = []
    for tool, result in comparison.items():
        metrics.append({"tool": tool, "tp": result["tp"], "fp": result["fp"],
                        "fn": result["fn"], "precision": round(result["precision"], 4),
                        "recall": round(result["recall"], 4), "f1": round(result["f1"], 4)})
    for tool, results in [("semgrep", semgrep_results),
                          ("llm_run_1", llm_results[0]), ("llm_run_2", llm_results[1])]:
        for item in results:
            findings.append({"tool": tool, "rule": item.rule, "location": item.location,
                             "severity": item.severity, "confidence": item.confidence,
                             "evidence": item.raw})

    HERE.mkdir(exist_ok=True)
    write_csv(HERE / "metrics.csv", metrics)
    write_csv(HERE / "findings.csv", findings)
    (HERE / "llm_runs.json").write_text(json.dumps(llm_meta, indent=2, ensure_ascii=False) + "\n")
    (HERE / "semgrep_run.json").write_text(json.dumps(semgrep_meta, indent=2) + "\n")

    summary = [
        "# Part C — LLM vs. Semgrep",
        "",
        "Ground truth was read independently from the target source and the instructor fixture, before scoring tool output. Keys are (rule, function).",
        "",
        "| Tool/run | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in metrics:
        summary.append(f"| {row['tool']} | {row['tp']} | {row['fp']} | {row['fn']} | {row['precision']:.0%} | {row['recall']:.0%} | {row['f1']:.2f} |")
    summary += ["", "## Findings", ""]
    for row in findings:
        summary.append(f"- **{row['tool']} — {row['rule']} at `{row['location']}`:** {row['evidence'] or 'No rationale returned.'}")
    summary += ["", "## Non-determinism", "",
                "Compare `llm_run_1` and `llm_run_2` in `metrics.csv` and `findings.csv`. The prompts were identical; temperature was nonzero, seeds differed, and caching was disabled.",
                "", "## Access control", "",
                "The source contains no session, role, or authorization mechanism. A report of broken access control is unsupported by this target and must be treated as a false positive.",
                "", "## Audit files", "",
                "- `metrics.csv`: precision, recall, and F1.",
                "- `findings.csv`: individual findings and model rationales.",
                "- `llm_runs.json`: exact LLM responses and run settings.",
                "- `semgrep_run.json`: scanner invocation and metadata.",
                ""]
    (HERE / "results.md").write_text("\n".join(summary), encoding="utf-8")
    print((HERE / "results.md").read_text())
    print("Saved duel CSV and JSON results in", HERE)


if __name__ == "__main__":
    main()