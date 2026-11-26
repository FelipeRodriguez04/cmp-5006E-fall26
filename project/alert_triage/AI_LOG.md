# AI Assistance Log

## Capstone — API token check

**Tool:** Codex.

**What I asked:** Create a Python file to check whether the API requires a
bearer token and accepts the token configured on the server.

**What I got:** The HTTP checks in `check_http.py` start a local server with
a generated token. They verify that a request without a token returns HTTP 401
and that a request with the configured token can read the queue.

**What I did with it:** I checked the same behavior manually with `curl`.
The API returned HTTP 401 until I loaded the server's token in the terminal
where I was sending requests. With the token set, I submitted `E01` and
confirmed it appeared in the queue.

**Did I understand it?** Each terminal has its own variables. The value sent
in the `Authorization` header must match the token used to start the server.

## Capstone — Comparing the baseline, model, and hybrid

**Tool:** Codex.

**What I asked:** Help me create a Python file that evaluates three approaches
to alert triage: the rule-based baseline, Ollama alone, and Ollama with the
server's priority policy.

**What I got:** The `evaluate.py` script runs the 24 catalog alerts five times
each and compares the three approaches against the same `expected_review`
labels. It reuses each Ollama response for the model and hybrid approaches
and saves the individual decisions and metrics in `evaluation.json`.

**What I did with it:** I reviewed `summary.comparison` and used alert `E05`
to trace how a single trial contributes to each approach's results.

**Did I understand it?** Each approach gets its own score against the catalog's
expected label. For `E05`, the baseline's `routine` label counted as a missed
alert, while the model's and hybrid's `urgent` labels counted as correct
detections.

## Capstone — Testing changes to alert notes

**Tool:** Codex.

**What I asked:** Help me create a Python file that changes alert notes while
keeping the sensor data fixed and compares the server's decisions with and
without the `sensor_review` flag.

**What I got:** The `check_notes.py` script runs the notes through Ollama and
applies both versions of the policy to each response. It saves the notes,
recommendations, and before-and-after priorities in `note_evaluation.json`.

**What I did with it:** I reviewed the `E05` example to see what happens when
an incomplete note leads Ollama to recommend `routine`.

**Did I understand it?** Only the note changes in the input to Ollama. The
evaluator uses the same model response for both policies. For the `E05`
example, the old policy accepted `routine` and the review floor raised it to
`review`.

## Capstone — Checking the HTTP priority policy

**Tool:** Codex.

**What I asked:** Help me create a Python file that sends requests to the local
triage API and checks the final priority for different simulated model outputs.

**What I got:** The `check_policy.py` script tests 20 simulated model outputs
against three alerts, with five repetitions per combination. It records all
300 HTTP checks in `policy_evaluation.json`.

**What I did with it:** I traced the `E05` example to see how a simulated
`ROUTINE` response becomes the recognized label `routine` and ends with a final
priority of `review`.

**Did I understand it?** `CASES` pairs each simulated output with the label the
API should recognize. `EXPECTED` maps that label to the final priority for each
alert. The script compares both expected values with the actual API response.
