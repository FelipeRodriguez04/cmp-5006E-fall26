# Week 8 — Control Scorecard

The shared pattern is to verify an artifact against values pinned by the
defender. Inventory identifies which artifacts need review; inventory alone
does not prevent installing compromised code.

| Attack | Trusted name | Substituted artifact | Pin / control | Conditional guarantee (axis 2) |
|---|---|---|---|---|
| Dependency confusion | `acme-auth` | Attacker's public `9.9.9` package | Lockfile with version, hash, and source | Only the approved hash and source are accepted, provided the lockfile is intact and the supplied hash matches the downloaded bytes. |
| Compromised transitive dependency (XZ) | An apparently trusted indirect dependency | Compromised upstream code | SBOM to locate it; provenance review and pinning to approve it | Traversal enumerates every reachable node if the graph is complete; the query identifies names in `KNOWN_BAD`. It does not guarantee that a package has no backdoors. |
| JWT `alg=none` | Token's `alg` field | Unsigned token with `role=admin` | Server-side HS256 pin and HMAC comparison | Only JSON objects authenticated under `SECRET` are returned, provided the key remains secret and sufficiently strong. |

## Dependency confusion

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | Attacker publishes the same name with a higher version; does not control the internal registry. | Same adversary; defender controls the lockfile. | `data.py`, provided guarantee test. |
| Guarantee | Highest version wins regardless of source. | Source and hash must match the lockfile, under the conditions above. | `resolve_pinned` in `starter.py`. |
| Coverage | Public package wins: `public`, `9.9.9`. | All three incorrect source/hash combinations and an unpinned package are rejected. | Additional checks performed during development; not a corpus of ≥20 attacks. |
| Bypass | The name is enough to substitute the package. | Internal source + bad hash and good hash + public source attempts rejected. Changing the lockfile or lying about the hash is outside the implemented control. | Checks performed during development. |
| FP cost | Attacker's artifact allowed. | 0/1 approved artifacts rejected in the fixture. Updates require refreshing the pin. | Provided lockfile test. |
| Op cost | Queries both registries. | One dictionary lookup and two comparisons; latency not measured. | Inspection of `resolve_pinned`. |
| Observability | Demo prints source and version. | Returns acceptance/rejection reason; demo prints it. No persistent logs. | `python3 starter.py`. |
| Failure mode | Trusts the wrong source. | Rejects missing packages and mismatches. Does not hash actual files. | Lockfile checks and function contract. |

## SBOM and transitive risk

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | Compromised code arrives through an indirect dependency. | Defender has a graph and a list of names known to be affected. | `dep_graph`, `KNOWN_BAD` in `data.py`. |
| Guarantee | Inspecting only direct dependencies misses `xz-utils`. | Complete transitive inventory relative to the supplied graph, excluding duplicates and the root. | `build_sbom` and provided test. |
| Coverage | `xz-utils` is not a direct dependency. | All six expected packages listed and `xz-utils` found; cycles and missing leaf entries handled too. | `test_sbom_finds_transitive_cve` and cycle check during development. |
| Bypass | Hiding a package at another level makes discovery harder. | Depth does not hide it. An incomplete graph or a name missing from the advisory can evade detection; provenance verification is not implemented. | Traversal and intersection inspected; duplicate/cyclic node check. |
| FP cost | No systematic query. | 0/5 healthy names flagged in the fixture; 1/1 known affected names detected. Does not distinguish safe versions of the same package. | Comparison of `SBOM_EXPECTED` with `KNOWN_BAD`. |
| Op cost | Manual investigation. | O(V+E) traversal, O(V log V) sorting, worst-case O(V+E) memory; no benchmark. | Inspection of stack traversal. |
| Observability | Indirect dependency has little visibility. | Demo prints inventory and affected names; no automatic alert or installation blocking. | `python3 starter.py`. |
| Failure mode | Transitive risk goes unnoticed. | Incomplete graph or advisory produces silent false negatives. An empty result does not certify safety. | `graph.get(..., [])` and name-based query. |

## Unsigned JWT

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | Remote attacker constructs header, payload, and signature without knowing the key. | Same adversary; server controls algorithm and key. | `forge_alg_none_admin`. |
| Guarantee | Token decides whether its signature is verified. | Only HS256 with correct HMAC and an object payload; no authorization, expiry, issuer, or audience checks. | `verify_secure`. |
| Coverage | Unsigned administrator accepted. | Six variants rejected: altered payload, empty signature, `none` forgery, and `none`/`HS512`/`RS256` headers with valid HMAC. | Guarantee test and development checks; corpus smaller than 20. |
| Bypass | `alg=none` removes authentication. | Setting `expected_alg` to `none` is also rejected. Key possession allows signing arbitrary claims; expiry/replay are not covered. | Algorithm check during development; function limitations. |
| FP cost | Legitimate tokens accepted. | 0/3 legitimate payloads rejected, including a signed administrator and an empty object. | Legitimate token checks during development. |
| Op cost | `none` skips HMAC. | One HMAC-SHA256 and JSON decoding per valid token; no benchmark. | Inspection of `verify_secure`. |
| Observability | Demo shows forged administrator. | Returns `None` on rejection; demo shows result. No reason logging or alerts. | `python3 starter.py`. |
| Failure mode | Fails open for `none`. | Fails closed for incorrect signature, unsupported algorithm, invalid structure, and non-object payload. | Malformed token and bypass checks during development. |

## Reproducible verification

From `studios/week-08`:

```bash
python3 test_supplychain.py
python3 starter.py
```

Result: all four provided tests pass. Additional checks were run during
development and are not included as a deliverable. The demo shows package
substitution and administrator escalation on the vulnerable paths, rejection on
the pinned paths, and discovery of the transitive dependency `xz-utils`.

A fourth example: a container image referenced as `:latest` can change contents.
Pinning the approved `sha256` digest binds deployment to those bytes; approving
the digest requires reviewing the artifact and its provenance.
