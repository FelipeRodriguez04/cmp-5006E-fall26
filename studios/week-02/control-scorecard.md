# One-Time Pad Control Scorecard

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | Passive attacker who can intercept communications and use unbounded computation, but cannot obtain the secret key or compromise an endpoint. | Unchanged. | Adversary capability stated in `README.md`; guarantee exercised in `test_otp.py`. |
| Guarantee | No confidentiality. | Perfect secrecy: the ciphertext is statistically independent of the plaintext, even against unbounded computation, **provided that** the key is truly random, at least as long as the message, kept secret, and used exactly once. | `test_otp_perfect_secrecy_when_key_used_once` in `test_otp.py` demonstrates that the same ciphertext can decrypt to different meaningful messages under different keys. |
| Coverage | 0% of an intercepted plaintext is protected. | Protects every plaintext bit when all conditions of the one-time pad are satisfied. | The perfect-secrecy argument and `test_otp_perfect_secrecy_when_key_used_once` in `test_otp.py`. |
| **Bypass** | No bypass is needed because the message is exposed. | Cause or exploit key reuse; then compute `c1 XOR c2 = p1 XOR p2` and use crib-dragging to recover the plaintexts. | `test_two_time_pad_leaks_and_crib_drag_recovers` in `test_otp.py`. |
| FP cost | Not applicable; there is no control. | Not applicable because the OTP does not classify or block messages. Using the wrong key instead corrupts the decrypted message. | No false-positive classifier is involved; a numerical FP rate was not measured in this studio. |
| Op cost | No key-generation, storage, or distribution cost. | Requires generating, securely distributing, storing, tracking, and destroying one truly random secret key bit for every plaintext bit; encryption and decryption themselves are linear-time XOR operations. | Key-length requirement in `README.md`; XOR implementation in `otp.py`. Latency and resource use were not measured. |
| Observability | No encryption failure to monitor. | The cipher provides no built-in indication that a key was reused or compromised; detecting reuse requires external key-management records and unique key identifiers. | The reuse test shows that plaintext relationships leak without producing an error or alert. |
| Failure mode | Plaintext is directly exposed. | **Silently degrades and alerts nobody:** key reuse gives `c1 XOR c2 = p1 XOR p2`, enabling a total break through crib-dragging. | `test_two_time_pad_leaks_and_crib_drag_recovers` in `test_otp.py`. |

## Why is the one-time pad rarely deployed?

Key distribution is as difficult as securely distributing the message itself. The parties must securely share as much secret, truly random key material as they have plaintext, and every part of that key must be tracked and used exactly once.
