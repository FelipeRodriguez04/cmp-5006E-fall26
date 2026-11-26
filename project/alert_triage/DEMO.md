# Ten-Minute Demo

| Time | What to show |
| --- | --- |
| 0–2 min | Introduce the catalog. Show a canary file access event and an authorized high-volume backup. |
| 2–4 min | Submit E01 and E10 with Ollama running. Open the queue and point out the final priority, the model recommendation, and the reason for each decision. |
| 4–6 min | Run `check_http`. Explain why the server keeps protected alerts at `urgent` or `review` when the model recommends `routine`, and what happens if Ollama is unavailable. |
| 6–8 min | Compare the rules, model, and hybrid results. Show a false positive and a false negative from the initial comparison, then show the before-and-after results from the note evaluation. |
| 8–10 min | Explain the sensor trust boundary, the manual review workload created by the fallback, and the disclosure decision. |
