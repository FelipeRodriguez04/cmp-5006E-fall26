"""Week 8 studio — starter (three attacks, three pins).

Fill in the functions below. Then run ``python3 test_supplychain.py``. All
provided tests must pass, INCLUDING the guarantee tests that watch a *name*-based
trust decision get exploited: the naive resolver installs the attacker's public
package, and the header-trusting verifier accepts an unsigned admin token. The
matching pin then forces the vetted artifact / rejects the forgery.

Nothing you write breaks a cryptographic primitive. Every exploit substitutes an
artifact behind a name the victim trusted; every fix pins the artifact instead of
trusting the name.
"""
import hashlib
import hmac
import json
import binascii

from data import (internal_registry, public_registry, LOCKFILE, SECRET,
                   dep_graph, KNOWN_BAD)
from supplychain import b64, b64d, make_token


# ---- Task 1a: dependency confusion — the naive resolver (the bug) -----------

def resolve_highest_version(pkg: str):
    """Resolve ``pkg`` by considering BOTH registries and picking the highest
    version, IGNORING the source. This is essentially the default installer
    behavior that made dependency confusion work at scale.

    Return ``(source, version)`` — e.g. ``("public", "9.9.9")`` for "acme-auth",
    because the attacker's public 9.9.9 outranks your internal 1.4.2.

    Recipe:
      1. Collect candidates ``("internal", v)`` / ``("public", v)`` when present.
      2. Return the candidate with the greatest version, comparing versions as
         tuples of ints, e.g. ``tuple(int(x) for x in "1.4.2".split("."))``.
    """
    candidates = [(source, registry[pkg])
                  for source, registry in (("internal", internal_registry),
                                           ("public", public_registry))
                  if pkg in registry]
    if not candidates:
        raise ValueError(f"Package not found: {pkg}")
    return max(candidates, key=lambda item: tuple(map(int, item[1].split("."))))


# ---- Task 1b: the pin — resolve against the lockfile (the fix) --------------

def resolve_pinned(pkg: str, candidate_hash: str, candidate_source: str):
    """Resolve ``pkg`` against the LOCKFILE instead of by name+version. Only the
    exact artifact you vetted (right source AND right hash) is accepted.

    Return ``(ok: bool, reason: str)``. Reject when:
      * the package is not in the lockfile at all,
      * the source does not match the pinned source, or
      * the hash does not match the pinned sha256.
    Accept only when source AND hash both match the lockfile entry.
    """
    pin = LOCKFILE.get(pkg)
    if pin is None:
        return False, "Package is not in the lockfile"
    if candidate_source != pin["source"]:
        return False, "Source does not match the lockfile"
    if candidate_hash != pin["sha256"]:
        return False, "Hash does not match the lockfile"
    return True, f"Accepted vetted artifact {pkg}=={pin['version']}"


# ---- Task 2: SBOM — build the transitive list, then query it for a CVE ------

def build_sbom(root: str, graph: dict) -> list:
    """Return the sorted list of ALL transitive dependencies of ``root`` (every
    package reachable in ``graph``, not just the direct ones). This is the
    inventory a real SBOM captures.

    Hint: walk the graph recursively (or with a stack), collecting names into a
    set, then ``sorted(...)`` it. Do not include ``root`` itself.
    """
    visited = {root}
    pending = list(graph.get(root, []))
    while pending:
        dependency = pending.pop()
        if dependency in visited:
            continue
        visited.add(dependency)
        pending.extend(graph.get(dependency, []))
    return sorted(visited - {root})


def cve_affected(sbom: list, known_bad: set) -> list:
    """Given an SBOM and a set of known-bad package names (a CVE advisory),
    return the sorted list of packages in the SBOM that are affected. With an
    SBOM this is an instant query; without one it is days of grepping build logs.
    """
    return sorted(set(sbom) & known_bad)


# ---- Task 3a: forge an alg=none admin token (the attack) --------------------

def forge_alg_none_admin() -> str:
    """Forge a token that the header-trusting ``verify_insecure`` will accept as
    an ADMIN, WITHOUT the signing key. Set the header ``alg`` to ``"none"``, the
    payload ``role`` to ``"admin"``, and send an EMPTY signature.

    Return the token string ``f"{header}.{payload}."`` (note the trailing dot —
    the empty third segment). Use ``b64(...)`` from ``supplychain`` and
    ``json.dumps(...).encode()`` to build the two segments.
    """
    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"user": "alice", "role": "admin"}).encode())
    return f"{header}.{payload}."


# ---- Task 3b: the pin — verify with a server-side algorithm (the fix) -------

def verify_secure(token: str, expected_alg: str = "HS256"):
    """Verify ``token`` by pinning the algorithm SERVER-SIDE. Never trust the
    token's own header. Reject anything whose header ``alg`` is not
    ``expected_alg`` (so ``alg=none`` is refused outright), then check the HS256
    signature under the server ``SECRET``.

    Return the payload dict on success, or ``None`` on rejection. You will need
    ``hmac``, ``hashlib``, ``json`` and the ``b64``/``b64d`` helpers plus
    ``SECRET`` — import them here.
    """
    # This verifier implements only HS256, even if misconfigured by its caller.
    if expected_alg != "HS256":
        return None
    try:
        header, payload, signature = token.split(".")
        claims_header = json.loads(b64d(header))
        if not isinstance(claims_header, dict) or claims_header.get("alg") != expected_alg:
            return None
        expected = b64(hmac.new(SECRET, f"{header}.{payload}".encode(),
                                hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(b64d(payload))
        return claims if isinstance(claims, dict) else None
    except (ValueError, TypeError, AttributeError, binascii.Error):
        return None


if __name__ == "__main__":
    # Task 1: watch the attacker's public package win, then the pin refuse it.
    try:
        src, ver = resolve_highest_version("acme-auth")
        print(f"naive resolve('acme-auth') -> {src} v{ver} "
              f"(attacker won: {src == 'public'})")
    except NotImplementedError:
        print("resolve_highest_version: not implemented yet")
    try:
        print("pinned, attacker's public:", resolve_pinned("acme-auth", "evil99ff", "public"))
        print("pinned, vetted internal  :", resolve_pinned("acme-auth", "aa11bb22cc", "internal"))
    except NotImplementedError:
        print("resolve_pinned: not implemented yet")

    # Task 2: SBOM + CVE query.
    try:
        sbom = build_sbom("our-app", dep_graph)
        print("SBOM:", sbom)
        print("affected by xz-utils CVE:", cve_affected(sbom, KNOWN_BAD))
    except NotImplementedError:
        print("build_sbom / cve_affected: not implemented yet")

    # Task 3: forge, then pin.
    from supplychain import verify_insecure
    legit = make_token({"user": "alice", "role": "user"})
    try:
        forged = forge_alg_none_admin()
        print("naive verifier accepts forgery as:", verify_insecure(forged))
    except NotImplementedError:
        print("forge_alg_none_admin: not implemented yet")
    try:
        print("pinned verifier, forgery:", verify_secure(forged))
        print("pinned verifier, legit  :", verify_secure(legit))
    except NotImplementedError:
        print("verify_secure: not implemented yet")
