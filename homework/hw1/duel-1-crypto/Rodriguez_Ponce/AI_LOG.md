## Homework 1 — Converting hexadecimal to bytes

**Tool:** Codex.
**What I asked:** How to convert a hexadecimal string to bytes in Python.
**What I got:** Use `bytes.fromhex(hex_string)`. Each pair of hexadecimal
characters represents one byte. For example, `bytes.fromhex("d8f6f831")`
produces four bytes. Use `.hex()` to convert bytes back to hexadecimal.
**What I did with it:** Related the explanation to
`ciphertext = bytes.fromhex(ciphertext_hex)` in `breaks/ecb_leak.py`.
**Did I understand it?** Yes. `bytes.fromhex()` converts each pair of hexadecimal
characters into one byte, and `.hex()` converts bytes back into hexadecimal text.

## Homework 1 — Constructing forged data

**Tool:** Codex.
**What I asked:** Help construct the forged data for the token MAC attack.
**What I got:** Code to calculate the zero padding using the secret length of 9
given in the exercise, then combine `data + padding + b"&role=admin"`.
**What I did with it:** Used this construction for `forged_data` in
`breaks/token_forge.py`.
**Did I understand it?** The padding depends on the combined length of the secret
and the original data, because the server hashes both together. The forged data
includes the original data, that padding, and `&role=admin`; the secret itself is
not included in what I send.

## Homework 1 — Crib-dragging

**Tool:** Codex.
**What I asked:** Help implement crib-dragging for the reused-pad attack.
**What I got:** Code that XORs two ciphertexts, slides guessed plaintext
fragments across the result, and checks for lowercase letters and spaces.
**What I did with it:** Used the implementation in `breaks/reused_pad.py` to
recover the target prefix and decrypt `msg1`, assuming the cribs are correct.
**Did I understand it?** The main idea is that XORing two ciphertexts encrypted
with the same pad cancels the pad. Sliding a guessed phrase across that result
produces possible fragments of the other message. Recovery depends on correct
guesses; readable text alone is not proof. The last target byte remains unknown
because none of the other messages reaches that position.
