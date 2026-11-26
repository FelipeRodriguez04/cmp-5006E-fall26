# Security Alert Triage

This local simulator models an analyst's alert queue. Ollama reads a note and
recommends a priority. The server keeps confirmed canary file access and
confirmed privileged changes at `urgent`. The catalog also flags corroborated
events that require at least `review`. When the model fails, the server sends
other alerts to manual review. The queue is stored in memory and clears on restart.

You need Python 3.10 or later, Ollama running at `127.0.0.1:11434`, and the
`qwen2.5:1.5b` model. In the first terminal, run the following from the
repository root. Copy the token printed before the server starts.

```sh
ollama pull qwen2.5:1.5b
export ALERT_TRIAGE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
printf '%s\n' "$ALERT_TRIAGE_TOKEN"
python3 -B -m project.alert_triage.app
```

Leave the server running. In a second terminal using Bash or Zsh, run these
commands, paste the token from the first terminal, and press Enter.

```sh
printf 'Paste the server token: '
read -rs ALERT_TRIAGE_TOKEN
printf '\n'
```

Each terminal has its own variables. Generate the token once and reuse the
same value in the second terminal. If the API returns HTTP 401 with
`{"error": "authentication required"}`, check that the second terminal has
the exact token used to start the server.

In the second terminal, submit a catalog alert and view the queue.

```sh
curl -sS http://127.0.0.1:8087/triage \
  -H "Authorization: Bearer $ALERT_TRIAGE_TOKEN" \
  -H 'Content-Type: application/json' -d '{"id":"E01"}'
curl -sS http://127.0.0.1:8087/queue -H "Authorization: Bearer $ALERT_TRIAGE_TOKEN"
```

`POST /triage` accepts a catalog ID and an optional note of up to 500
characters. If you omit the note, the server uses the scenario's default note.
Resubmitting an ID replaces its queue entry. `GET /queue` sorts by priority
and then by ID. Use only synthetic data.

```sh
python3 -B -m project.alert_triage.check_http
python3 -B -m project.alert_triage.evaluate
python3 -B -m project.alert_triage.check_notes
python3 -B -m project.alert_triage.check_policy
python3 -B -m project.alert_triage.check_injections
```

- `check_http` checks the HTTP contract with controlled model responses.
- `evaluate` runs the baseline comparison with Ollama and writes [evaluation.json](evaluation.json).
- `check_notes` compares the old and revised policies on the same model responses and writes [note_evaluation.json](note_evaluation.json).
- `check_policy` tests the HTTP policy with 20 simulated model outputs and writes [policy_evaluation.json](policy_evaluation.json).
- `check_injections` runs 20 injection payloads five times each with Ollama and saves all 100 inferences in [injection_evaluation.json](injection_evaluation.json).

See the [report](REPORT.md) and the [demo script](DEMO.md).
