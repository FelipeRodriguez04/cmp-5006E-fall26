"""Week 11 studio — starter (four privacy attacks + one measurement).

Fill in the functions below, then run ``python3 test_privacy.py``. All provided
tests must pass, INCLUDING the two that pin the week's spine against each other:

  * differential privacy bounds the change in output-event probabilities by a
    factor of e^ε. For this count, the expected absolute error is 1/ε; and
  * k-anonymity **only raises cost** — it protects identity but has NO guarantee
    about the secret, and the homogeneity attack watches it leak the diagnosis.

Nothing here touches real personal data — every dataset is synthetic (``data.py``).
"""
from collections import Counter, defaultdict

from privacy import epsilon_guarantee, generalize, laplace_noise, membership_guess, quasi_id


# ---- Task 1: re-identify by linkage ----------------------------------------

def reidentify(released, voter_roll):
    """Link the 'anonymized' ``released`` medical table to the public ``voter_roll``
    on the quasi-identifier {zip, yob, sex}, and re-identify a victim.

    Return a dict with:
      * ``"fraction_unique"`` — share of released records that are UNIQUE on the
        quasi-id (uniqueness is what makes a row linkable). ~0.75 here.
      * ``"victim"``          — the first uniquely-identified released record.
      * ``"victim_name"``     — the name that record links to in the voter roll.
        This is the ORACLE: a re-identification is confirmed by a successful NAME
        link, not by "this row looks unique".

    When the voter roll supplies zero or multiple distinct names for a given
    quasi-id, that record cannot confirm a name link.
    """
    released = list(released)
    counts = Counter(quasi_id(row) for row in released)
    names = defaultdict(set)
    for voter in voter_roll:
        names[quasi_id(voter)].add(voter["name"])

    unique_rows = [row for row in released if counts[quasi_id(row)] == 1]
    victim = next((row for row in unique_rows if len(names[quasi_id(row)]) == 1), None)
    return {
        "fraction_unique": len(unique_rows) / len(released) if released else 0.0,
        "victim": victim,
        "victim_name": next(iter(names[quasi_id(victim)])) if victim is not None else None,
    }


# ---- Task 2: k-anonymize, then break it with the homogeneity attack --------

def homogeneity_attack(group):
    """A k-anonymous ``group`` (list of records sharing a generalized quasi-id, so
    no member is unique) is handed to you. Mount the homogeneity attack: if every
    member shares the SAME sensitive value, you learn it WITHOUT singling anyone
    out — k-anonymity protected identity, not the attribute.

    Return the single leaked ``diagnosis`` if the group is uniform on it, else
    ``None`` (a diverse group does not leak — that is what l-diversity buys).

    State in your write-up exactly what k-anonymity did (hid identity: k = len(group),
    no unique row) and did NOT do (bound what the attacker learns).
    """
    diagnoses = {row["diagnosis"] for row in group}
    return diagnoses.pop() if len(diagnoses) == 1 else None


# ---- Task 3: differential privacy — a statable guarantee -------------------

def noisy_count(true_count, eps, rng):
    """Answer a COUNT query under ε-differential privacy. A count has sensitivity
    1 under add/remove adjacency, so the Laplace scale is 1/ε.

    Smaller ε -> more noise -> stronger privacy, less accuracy. The mean absolute
    error equals 1/ε in expectation.
    """
    return true_count + laplace_noise(1.0 / eps, rng)


# ---- Task 4: membership inference on the simulated model -------------------

def membership_inference(probe, thresholds):
    """Mount the loss-threshold membership-inference attack on the simulated
    model's ``probe`` (each record has a ``loss`` and a ground-truth ``member``
    flag). For each candidate threshold, guess 'member' when loss < threshold
    (``membership_guess``); pick the threshold with the best accuracy.

    Return a dict: ``{"best_threshold": t, "accuracy": a}``. Beating the 50%
    baseline means the MODEL leaked training membership — a breach with no table
    involved. For a 'diabetes model', being in the training set IS the secret.
    """
    probe = list(probe)
    best_threshold = None
    best_correct = -1
    for threshold in thresholds:
        correct = sum(membership_guess(row, threshold) == row["member"] for row in probe)
        if correct > best_correct:
            best_threshold, best_correct = threshold, correct
    if not probe or best_correct < 0:
        raise ValueError("probe and thresholds must both be nonempty")
    return {"best_threshold": best_threshold, "accuracy": best_correct / len(probe)}


if __name__ == "__main__":
    import random
    from data import (RELEASED, VOTER_ROLL, PROBE, HOMOGENEOUS_GROUP,
                      DP_EPSILONS, TRUE_HIV_COUNT, MI_THRESHOLDS)

    res = reidentify(RELEASED, VOTER_ROLL)
    print(f"Unique released rows: {res['fraction_unique']:.0%}. "
          f"Confirmed link: {res['victim_name']} (diagnosis {res['victim']['diagnosis']!r})")

    groups = Counter(generalize(row) for row in RELEASED)
    print(f"Generalized release: {len(groups)} groups, smallest size {min(groups.values())}")
    print(f"Constructed k={len(HOMOGENEOUS_GROUP)} group reveals "
          f"{homogeneity_attack(HOMOGENEOUS_GROUP)!r}")
    diverse_group = [
        dict(row, diagnosis=diagnosis)
        for row, diagnosis in zip(HOMOGENEOUS_GROUP, ("hiv", "flu", "none", "cancer", "diabetes"))
    ]
    print("Diverse group homogeneous disclosure:", homogeneity_attack(diverse_group))

    print(f"DP count of HIV (true = {TRUE_HIV_COUNT}):")
    for eps in DP_EPSILONS:
        rng = random.Random(1)
        errors = [abs(noisy_count(TRUE_HIV_COUNT, eps, rng) - TRUE_HIV_COUNT)
                  for _ in range(5000)]
        print(f"  eps={eps:>4}  mean|error|={sum(errors)/len(errors):>6.2f}  "
              f"(expected 1/eps = {1/eps})")

    rng = random.Random(1)
    query_count = 10
    eps_per_query = 0.1
    answers = [noisy_count(TRUE_HIV_COUNT, eps_per_query, rng) for _ in range(query_count)]
    total_eps = query_count * eps_per_query
    print(f"Ten releases at eps={eps_per_query} each: "
          + ", ".join(f"{answer:.2f}" for answer in answers))
    print(f"Composition: eps={eps_per_query} -> {total_eps:g}, "
          f"likelihood factor {epsilon_guarantee(eps_per_query):.3f} "
          f"-> {epsilon_guarantee(total_eps):.3f}")

    mi = membership_inference(PROBE, MI_THRESHOLDS)
    print(f"Membership inference: {mi['accuracy']:.1%} accuracy "
          f"(baseline 50%) at threshold {mi['best_threshold']}")
