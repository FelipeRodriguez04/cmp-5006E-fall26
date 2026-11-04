# AI Assistance Log

## Homework 2 — Medium adaptation

**Tool:** Codex.

**What I asked:** Help me implement a Medium adaptation of the course vuln-web target.

**What I got:** Help adding local filters in `target.py` while reusing the
course application's existing handlers and database. The SQLi filter rejects
uppercase `OR` and `UNION` in login inputs, the XSS filter removes the exact
strings `<script>` and `</script>`, and the command injection filter rejects
semicolons in the host. The assistant explained that these filters are
intentionally bypassable and that this is a student adaptation, since the
original target has no Medium mode.

**What I did with it:** Included the adaptation in my submission and documented
its rules and limitations in the README. The recorded tests show that the
original control payloads lose their attack effect and that the lowercase SQLi,
mixed-case XSS, and pipe-based command injection bypasses succeed in three out
of three trials. 

**Did I understand it?** Yes. After reviewing the code and the additional
explanations, I understand how `target.py` applies the local Medium filters:
rejecting uppercase `OR` and `UNION` in login inputs, removing exact lowercase
script tags from the name, and rejecting semicolons in the host. I understand
why lowercase SQL keywords, mixed-case script tags, and a pipe bypass these
specific rules. 

## Homework 2 — HTTP test runner

**Tool:** Codex.

**What I asked:** Help me implement `run.py` to test the attacks and defenses
against the local target and save the results.

**What I got:** Help developing a runner that starts a temporary local server
and test database for each mode (`medium`, `waf`, and `positive`), sends HTTP
requests, and uses `seclab.attack.run_payloads` to repeat each attack three
times. The assistant helped implement response oracles for the SQLi canary,
unescaped script elements, and simulated command injection. The runner also
checks normal logins, measures false positives using `benign_traffic.json`,
and saves CSV results, JSON responses, and execution metadata.

**What I did with it:** Included the assisted runner and its recorded outputs
in the submission. Used the saved results to document attack successes, WAF
bypasses, false-positive rates, and the failure of the tested attacks in
positive mode. 

**Did I understand it?** Yes. After the walkthrough, I understand how `run.py`
starts the local target using the adapted course handlers and the course's
`make_db()` function, sends HTTP requests, and checks responses with custom
oracles through `seclab.attack`. I also understand how it repeats the attacks,
measures false positives, and saves the results.


## Homework 2 — Part C: understanding the LLM-vs-scanner comparison

**Tool:** ChatGPT (study support and implementation assistance).

**Practice question (reconstructed for this log):** "I understand that Semgrep searches source code using rules and that an LLM reads the code, but I don't understand precision, recall, F1, or why we need a ground-truth set. Can you explain it using our three vulnerabilities?"

**What I learned:** Ground truth is the hand-checked list of actual defects: SQL injection in `do_login`, reflected XSS in `do_reflect`, and command injection in `do_ping`. A true positive (TP) is a real finding reported by a tool. A false positive (FP) is a report that is not in the ground truth. A false negative (FN) is a real defect the tool missed.

- **Precision = TP / (TP + FP):** of everything the tool reported, how much was correct?
- **Recall = TP / (TP + FN):** of the real vulnerabilities, how many did the tool find?
- **F1:** the harmonic mean of precision and recall; it balances both measures.

For example, if a scanner reports two real findings and misses one, it has precision 100%, recall 2/3, and F1 0.80. A tool that reports all three real findings plus one invented finding has precision 3/4, recall 100%, and F1 about 0.86. This is why a high recall alone does not mean every reported issue is real.

**Non-determinism:** The same prompt is sent to the LLM twice with a nonzero temperature, different seeds, and caching disabled. I compare the two sets of findings rather than assuming the model always gives the same answer. The exact responses and metrics must come from `duel/llm_runs.json` and `duel/metrics.csv` after running the script; they are not pre-filled with invented results.

**What I did with it:** Added `duel/run_duel.py` and a focused Semgrep rule file. The runner calls `seclab.scan.compare_scanners`, uses the course ground truth, and saves the findings, metrics, exact LLM responses, and scanner metadata as CSV/JSON/Markdown files.

**Did I understand it?** Yes. The comparison is not a contest where the tool with the highest score is automatically best. I need to inspect the false positives and missed findings, check whether the ground truth was independent, and explain the limits of the test. In this application, broken access control should not be reported as a real issue because the source has no sessions, roles, or authorization mechanism.