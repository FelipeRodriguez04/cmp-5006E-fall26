# Week 11 Control Scorecard

All results come from the supplied synthetic datasets. The voter roll supplies
names and quasi-identifiers, the medical release supplies diagnoses, and the
simulated model supplies per-record losses.

| Defense | Guarantee (axis 2) | Failure or condition | Measured evidence |
|---|---|---|---|
| Drop names | Removes the explicit name field. Linkage can still identify people. | An observer can match a released record to auxiliary data on ZIP, birth year, and sex. | 90/120 released rows (75%) were unique on those fields. The voter roll confirmed a name link for synthetic `person001`, revealing `diabetes`. |
| k-anonymity | Each published quasi-identifier tuple is shared by at least k rows, for the selected fields. It raises the cost of singling out a row from those fields. | A shared diagnosis is inferable for every person known to belong to that group. | Generalization produced four groups with a minimum size of three. In the separate constructed group, five rows share a tuple and all five carry `hiv`. |
| Distinct l-diversity | Each group has at least l distinct sensitive values. This rules out homogeneous disclosure when l ≥ 2. | Skewed frequencies, similar diagnoses, and side information can still reveal sensitive information. | The group with five distinct diagnoses returned `None` under the same homogeneity check. |
| Differential privacy | For neighboring datasets that differ by one record, every output event has probability at most e^ε times its probability on the other dataset, in either direction. | This count has sensitivity 1 and uses fresh Laplace noise at scale 1/ε per release. Expected absolute error is 1/ε and privacy budgets add under sequential composition. | Mean absolute error fell from 10.17 at ε=0.1 to 0.20 at ε=5. Ten releases at ε=0.1 each give a total bound of ε=1. |

## Differential privacy measurements

Each row summarizes 5,000 simulated draws for the synthetic count of 24.

| ε | Measured mean absolute error | Expected mean absolute error |
|---:|---:|---:|
| 0.1 | 10.17 | 10.00 |
| 0.5 | 2.03 | 2.00 |
| 1 | 1.02 | 1.00 |
| 5 | 0.20 | 0.20 |

- At ε=0.1, adding or removing one record changes the probability of any
  output event by at most a factor of 1.105 in either direction.
- At ε=5, adding or removing one record changes the probability of any
  output event by at most a factor of 148.413 in either direction.

The guarantee limits how much the release can change the evidence for an
individual's membership, even when an adversary brings side information. The
expected absolute error describes average accuracy. A single draw can have a
larger error.

The composition demo released ten independently noised answers to the same
count at ε=0.1 each. The joint transcript has an ε=1 bound, giving a factor of
2.718 instead of the single-release factor of 1.105. One answer was −4.70.
If all ten queries had to fit within a **total** ε=0.1, equal allocation would
give ε=0.01 per query and an expected absolute error of 100 per answer.

## Membership inference

On the balanced simulated probe, a loss threshold of 0.6 gave 161 correct
predictions out of 200 (80.5%), 30.5 percentage points above the 50% baseline.
The same probe was used to select and score the threshold, so this is an
in-sample result. If a training dataset consists of patients with diabetes,
membership itself can reveal the diagnosis. A model trained with DP-SGD can
bound a record's influence when its privacy accountant establishes an
appropriate budget.
