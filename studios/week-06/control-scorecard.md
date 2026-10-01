# Week 06 Studio — Control Scorecard and Answers

## Checking the solution

From `studios/week-06`:

```bash
python3 test_studio.py
python3 starter.py
```

The first command runs the six provided tests. The second shows the SQLi, cmdi,
and XSS findings, followed by the Task 2 comparison under `== Duel ==`.

## Task 2 — LLM vs. scanner

The implementation is in `parse_llm_review` in `starter.py`: it converts the five
claims in `RAW_LLM_REVIEW` into structured results, including the incorrect
findings. At the end of `starter.py`, `compare_scanners` compares those results
and the regex scanner's results against the provided ground truth.

These numbers appear when running `python3 starter.py`:

| Tool | TP: true positives | FP: false positives | FN: missed bugs | Precision | Recall | F1 |
|------|--------------------|---------------------|-----------------|-----------|--------|----|
| Regex scanner | 2 | 0 | 1 | 100% | 67% | 0.80 |
| Provided LLM review | 3 | 2 | 0 | 60% | 100% | 0.75 |

The ground truth contains three real bugs: SQLi, XSS, and cmdi. The scanner finds
XSS and cmdi: both reported findings are correct (precision 2/2), but it detects
only two of the three bugs (recall 2/3). The LLM reports five findings: three real
and two false; its precision is therefore 3/5 and its recall is 3/3. F1 combines
precision and recall using `2 × precision × recall / (precision + recall)`.

Answers to the studio's three questions:

1. **What did the LLM hallucinate?** Broken Access Control in `do_login`, which
   is absent from the ground truth, and XSS in `do_reflect_safe`, even though
   that endpoint escapes HTML.
2. **What did the scanner miss that the LLM caught?** SQLi in `do_login`. The
   regex rule looks for `SELECT` and interpolation on the same line, but the
   query spans two lines.
3. **Did either find Broken Access Control truthfully?** No. The scanner does
   not report it, and the LLM's claim is a false positive against the ground
   truth. Since this fixture contains no real BAC example, it also cannot
   measure how much of that class either tool would detect in other applications.

## Task 3 — Control Scorecard, axes 1–4

Selected finding: reflected XSS at `GET /?name=`. Evaluated defense: `html.escape`
in the `/safe` endpoint, which inserts the input as text inside an `<h1>`.

| Axis | Before | After control | Evidence |
|------|--------|---------------|----------|
| Threat model | An attacker without credentials controls `name` and can build a link containing a script for a victim to open. | The attacker still controls `name`; the server encodes that input before inserting it into HTML. | `confirm_xss` sends the same payload through `reflect_send` and `reflect_safe_send`. |
| Guarantee | Input is inserted without escaping and can become HTML markup. | Input remains text **if** it is fully encoded with `html.escape` in this HTML text context and is not subsequently decoded or reused in an unsafe context. | `do_reflect_safe` uses `html.escape(name)`; the oracle does not confirm the script at `/safe`. |
| Coverage | The tests' single XSS payload remains unescaped at `/`: 0/1 payloads neutralized. | The same payload is escaped at `/safe`: 1/1 payloads neutralized in this sample. This does not mean 100% coverage of the entire XSS class. | `test_reflected_but_escaped_is_not_a_confirmed_xss` checks a confirmed finding at `/` and an unconfirmed finding at `/safe`. |
| Bypass | `<script>alert('XSS-FIRED-7f3a')</script>` passes through interpolation at `/` without encoding. | The same script was attempted at `/safe`; it did not bypass encoding. Tests of other variants are not presented here. | `confirm_xss`; the output of `python3 starter.py` shows `vulnerable / : CONFIRMED` and `fixed /safe : no effect`. |

**Where 1/1 comes from:** `confirm_xss` contains one distinct XSS payload.
It is sent to two endpoints to compare behavior before and after the defense.
Although `starter.py` repeats each request five times, this is still one distinct
payload; the tests print the confirmation outcome rather than repetition counts.

**Coverage limitation:** the general rubric in `resources/control-scorecard.md`
requires at least 20 distinct payloads. The current tests use one for XSS, so
this evidence is limited and does not meet that minimum. Figures from the
removed auxiliary evaluation were omitted so this document describes what can
be checked with the current files.

## Responsible disclosure note (two lines; unsent exercise)

During authorized testing of the lab, `GET /?name=` in `do_reflect` inserts an unescaped script into HTML, which may allow JavaScript execution in the browser of a victim who opens a crafted link.
I recommend encoding input with `html.escape` in this context, as `/safe` does; I would share minimal proof with the owner through a private channel and agree on a remediation window.

## Where we may have been unfair, and what we did not test.

- The LLM arm uses the review provided by the course; no live model was run.
  The scanner uses regex rules rather than Semgrep or sqlmap.
- The XSS oracle checks that a script survives unescaped in this HTML; it does
  not run a browser. The reported coverage applies to a single payload.
- cmdi is confirmed through a simulator; no shell is executed. SQLi extracts
  only the lab's synthetic canary.
