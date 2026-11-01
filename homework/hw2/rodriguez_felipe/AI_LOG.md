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
