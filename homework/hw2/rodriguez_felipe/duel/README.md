# Part C — Scanner vs. LLM

Run from the repository root:

```bash
python3 homework/hw2/rodriguez_felipe/duel/run_duel.py --backend ollama --model qwen2.5:1.5b
```

Requirements:
- Semgrep installed (`brew install semgrep` on macOS).
- Ollama installed and serving (`ollama serve`) with the selected model available (`ollama pull qwen2.5:1.5b` if needed).

For a different installed Ollama model, pass its exact name with `--model`.
For the manual backend, use `--backend manual`; the script will ask you to paste
two separate model answers. Do not use `echo` as evidence because it is not a
real model.

The script scans the same `vulnweb_app.py` source with a small custom Semgrep
rule set and an LLM. It scores the outputs using the hand-built course
`ground_truth.json`. The two LLM calls use different seeds, nonzero
temperature, and disabled caching.

Generated files:
- `metrics.csv` — TP, FP, FN, precision, recall, and F1.
- `findings.csv` — each reported finding.
- `llm_runs.json` — exact model responses and run settings.
- `semgrep_run.json` — Semgrep command metadata.
- `results.md` — readable summary.

The Semgrep rules are intentionally narrow and detect the SQLi and XSS patterns.
A missed command-injection finding is therefore a limitation of this rule set,
not a claim about every Semgrep rule pack. Review the actual outputs before
writing numeric results into the homework report.