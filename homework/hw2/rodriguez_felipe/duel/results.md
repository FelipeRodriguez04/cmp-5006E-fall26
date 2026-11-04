# Part C — LLM vs. Semgrep

Ground truth was read independently from the target source and the instructor fixture, before scoring tool output. Keys are (rule, function).

| Tool/run | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| semgrep | 2 | 0 | 1 | 100% | 67% | 0.80 |
| llm_run_1 | 2 | 0 | 1 | 100% | 67% | 0.80 |
| llm_run_2 | 3 | 0 | 0 | 100% | 100% | 1.00 |

## Findings

- **semgrep — sqli at `do_login`:** User-controlled values are interpolated into a SQL query.
- **semgrep — xss at `do_reflect`:** User input is returned in HTML without context-aware encoding.
- **llm_run_1 — sqli at `do_login`:** SQL injection due to the use of string-formatted query without parameterization.
- **llm_run_1 — xss at `do_reflect`:** Reflected XSS due to the use of unencoded user input in the HTML.
- **llm_run_2 — sqli at `do_login`:** do_login function is vulnerable to SQL injection and reflected XSS due to the use of unparameterized queries and input not being properly sanitized.
- **llm_run_2 — xss at `do_reflect`:** do_reflect function is vulnerable to reflected XSS due to the lack of input sanitization.
- **llm_run_2 — cmdi at `do_ping`:** do_ping function is vulnerable to command injection because the host input is concatenated into a command without proper sanitization.

## Non-determinism

Compare `llm_run_1` and `llm_run_2` in `metrics.csv` and `findings.csv`. The prompts were identical; temperature was nonzero, seeds differed, and caching was disabled.

## Access control

The source contains no session, role, or authorization mechanism. A report of broken access control is unsupported by this target and must be treated as a false positive.

## Audit files

- `metrics.csv`: precision, recall, and F1.
- `findings.csv`: individual findings and model rationales.
- `llm_runs.json`: exact LLM responses and run settings.
- `semgrep_run.json`: scanner invocation and metadata.
