# Week 4 — Control Scorecard

## RSA

The control is RSA with properly generated keys. Shared-factor attacks show why
its security depends on how the primes are chosen. Here, “Before” means weak
key generation and “After control” means proper key generation.

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | An attacker can collect public keys and try to recover private keys. | The attacker still knows the public keys. | The shared-factor attack needs only public information. |
| Guarantee | Weak key generation can expose private keys. | Factoring an RSA-2048 modulus should be infeasible if its primes are large, random, and independently chosen. | Shared primes break this condition, as the lab demonstrates. |
| Coverage | Keys with shared primes are vulnerable to GCD attacks. | Properly generated, independent primes make shared factors extremely unlikely; they do not prevent every RSA attack. | The lab demonstrates one attack, not a general protection rate. |
| Bypass | Poor randomness can cause prime reuse. | An attacker can target weak key generation or leaks in the implementation. | GCD reveals a shared prime and allows private-key recovery. |
| Cost — false positives | Not directly applicable: RSA does not classify attacks. | Proper key generation should not block legitimate use. | No false-positive rate applies to this control by itself. |
| Cost — operational | Generating and using RSA keys requires computation. | Secure randomness, prime generation, and key management also have costs. | Operational costs were not measured. |
| Observability | A compromised key may go unnoticed. | RSA itself does not alert on shared primes; a separate scan can detect them. | The lab scan identified the affected keys. |
| Failure mode | Weak keys can expose protected data. | If key-generation conditions fail, private keys may be recovered silently. | Both keys sharing a prime were recovered in the lab. |

## Secret comparison

The control is a comparison whose timing does not depend on secret contents.
The attack uses response times to learn which guesses match part of the secret.
“Before” means an early-exit comparison; “After control” means a constant-time
comparison.

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | An attacker can submit guesses repeatedly and measure response times. | The attacker keeps the same access. | The lab oracle provides these capabilities. |
| Guarantee | Stopping at the first mismatch can reveal the matching prefix. | Timing should not reveal which bytes match, provided the comparison and surrounding code do not take different paths based on secret contents. | The lab fix removes the early return on a mismatch. |
| Coverage | Timing can guide the next guess. | The control addresses comparison timing; it does not stop guessing or leaks elsewhere. | The tested timing attack failed after the fix; broader coverage was not measured. |
| Bypass | Longer matching prefixes take longer to process. | A remaining early return or another timing leak can still expose information. | The attack worked against the early-exit version. |
| Cost — false positives | Not directly applicable: this function compares values, rather than classifying attacks. | Constant-time comparison should not change which values are accepted. | Equality tests checked correctness; no false-positive rate was measured. |
| Cost — operational | Comparison can stop at the first difference. | Every byte must be checked, so work grows with input length. | Added latency and CPU usage were not measured. |
| Observability | Timing probes may look like ordinary failed guesses. | The comparison itself raises no alert; monitoring must happen elsewhere. | The lab comparator has no alerting. |
| Failure mode | The secret can leak silently. | If the constant-time condition fails, the function may return correct answers while still leaking information. | Correct equality results alone do not prove timing safety. |

## Lab evidence and required notes

- The shared-factor scan recovered keys **0 and 4**. All six provided tests passed.
- The timing attack worked with **41 rounds per candidate**. It recovered the
  three tested secrets before the fix and none after it.
- Scanning k keys requires `k(k − 1)/2` GCD comparisons: **O(k²)**. Doubling a
  large collection roughly quadruples the work. The Internet-scale method
  described in the README uses product and remainder trees to reuse calculations.

## Where we may have been unfair, and what we did not test.

The lab uses a small sample and makes timing differences easier to observe.
We did not test 20 distinct attack cases, a real network, or production costs.
Failure to recover a secret does not prove that no information leaks. The Python
fix is educational; production code should use `hmac.compare_digest`.
