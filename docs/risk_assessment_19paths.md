# Risk Assessment of the 19 Gap Paths

This document makes the study-specific NIST SP 800-30 Rev. 1 workflow
reproducible. The row-level scores are released in machine-readable form as
`data/risk_assessment_19paths.csv`; the external source keys are resolved in
`docs/risk_evidence_register.md`.

## 1. Assessment unit and workflow

The unit of analysis is one communication path and one stated threat scenario.
For each row:

1. score four likelihood factors from 1 to 5;
2. compute the arithmetic mean and convert it to a likelihood band;
3. score confidentiality, integrity, availability/grid, and impact scope from
   1 to 5;
4. set impact to the maximum of those four consequence scores; and
5. look up overall risk in the published 5×5 matrix.

This procedure is a study-specific operationalization informed by NIST SP
800-30 Rev. 1. NIST does not prescribe the numeric thresholds or the matrix
below.

## 2. Likelihood operational definitions

### Factor scores

| Score | Exposure / reachability | Attack feasibility (inverse complexity) | Deployment prevalence | Evidence strength |
|---:|---|---|---|---|
| 1 | no independent routed edge; only physical or highly indirect access | several rare prerequisites and specialized access | exceptional or conceptual deployment | conceptual relationship only |
| 2 | isolated/private edge or access through several trust boundaries | specialized access or several non-default preconditions | uncommon or product-specific | recognized architecture/use case without field evidence |
| 3 | reachable from an adjacent trust zone after one meaningful prerequisite | feasible with commodity tooling and domain knowledge | deployment-dependent but established | standard/guideline support or a documented class of incidents |
| 4 | routinely network-reachable in normal operation | practical remote attack with known protocol behavior | common across deployed architectures | peer-reviewed analysis, measured exposure, or documented vulnerabilities |
| 5 | public/ubiquitous exposure or very frequent contact opportunity | repeatable low-cost exploitation with minimal prerequisites | near-ubiquitous in the scoped population | repeated empirical exploitation across independent sources |

The four scores are equally weighted:

`Likelihood mean = (Exposure + Feasibility + Prevalence + Evidence) / 4`

### Mean-to-band conversion

| Mean range | Likelihood |
|---:|---|
| 1.00–1.49 | Very Low |
| 1.50–2.49 | Low |
| 2.50–3.49 | Moderate |
| 3.50–4.49 | High |
| 4.50–5.00 | Very High |

No rounding is applied before banding. The displayed mean is rounded to two
decimal places only after the band is assigned.

## 3. Impact operational definitions

Each consequence dimension is scored independently. Overall impact is the
maximum, because a path with one safety-, grid-, or trust-critical consequence
must not be averaged down by less affected dimensions.

| Score | Confidentiality | Integrity | Availability / grid | Impact scope |
|---:|---|---|---|---|
| 1 | no sensitive data | no operational decision depends on the data | negligible interruption | one noncritical function |
| 2 | limited non-personal operational data | local noncritical error | short single-device interruption | one device or transaction |
| 3 | limited PII, account, or operationally sensitive data | incorrect transaction or single-device control | site-level degradation or recoverable interruption | one site or a bounded user group |
| 4 | payment data, credentials, keys, or substantial PII | safety-relevant or multi-device/site control manipulation | sustained multi-site/fleet disruption | multiple sites, a fleet segment, or a feeder |
| 5 | systemic disclosure of fleet-wide secrets or highly sensitive data | grid- or safety-critical control corruption | grid instability, safety event, or systemic outage | fleet-, regional-, or grid-wide impact |

`Impact score = max(C, I, A/Grid, Scope)`

The score-to-label mapping is 1 = Very Low, 2 = Low, 3 = Moderate, 4 = High,
and 5 = Very High.

## 4. Overall-risk matrix

| Likelihood ↓ / Impact → | Very Low | Low | Moderate | High | Very High |
|---|---|---|---|---|---|
| Very Low | Very Low | Very Low | Low | Low | Moderate |
| Low | Very Low | Low | Low | Moderate | Moderate |
| Moderate | Low | Low | Moderate | Moderate | High |
| High | Low | Moderate | Moderate | High | High |
| Very High | Moderate | Moderate | High | High | Very High |

Accordingly, High likelihood × Very High impact = High overall risk. Only
the Very High × Very High cell is labeled Very High. This conservative ceiling
avoids claiming a catastrophic/near-certain combination without repeated
empirical evidence, while still selecting all four High rows for priority ZTA
design.

## 5. Row-level results

Likelihood sub-scores and all four impact sub-scores are in the CSV. This table
is a compact view of the same records.

| ID | Path | Gap | Scenario | Likelihood | Impact | Overall | Evidence |
|---:|---|---|---|---|---|---|---|
| 1 | CSMS ↔ Utility/Grid | A | Forged grid-linked charging-control command | High (4.00) | Very High | High | E07, E08, E09, E12 |
| 2 | EVSE/CS ↔ Utility/Grid | A | Manipulated demand-response or DER linkage data | High (4.00) | High | High | E07, E09, E13 |
| 3 | EVSE-Internal ↔ CSMS | A | Forged internal-component status reports | Moderate (3.00) | High | Moderate | E02, E05, E10 |
| 4 | CSMS ↔ PKI | A | Manipulated certificate-management requests or status | Low (2.00) | High | Moderate | E02 |
| 5 | SECC ↔ CSMS | B | Control-message injection through the charger-internal integration path | High (3.75) | High | High | E02, E03, E05, E10 |
| 6 | EVSE/CS ↔ Wireless | B | Man-in-the-middle on wireless backhaul or field access | High (4.25) | High | High | E02, E05, E11 |
| 7 | EVSE-Internal ↔ Utility/Grid | B | Manipulated grid-linkage commands for internal power components | Moderate (3.00) | High | Moderate | E07, E13, E14 |
| 8 | EVSE-Internal ↔ Wireless | B | Abuse of independent wireless access to internal components | Moderate (2.75) | High | Moderate | E04, E05 |
| 9 | EV-Internal ↔ Wireless | B | Abuse of telematics or in-vehicle wireless interfaces | Moderate (3.00) | High | Moderate | E04, E10 |
| 10 | EVSE/CS ↔ PKI | B | Abuse of charger certificate issuance or management | Moderate (3.00) | High | Moderate | E02 |
| 11 | EVSE/CS ↔ eMSP/External | B | Manipulated payment, roaming, or external-service data | Moderate (3.25) | High | Moderate | E16, E17 |
| 12 | EVSE-Internal ↔ PKI | B | Abuse of an internal-device certificate or security-module path | Low (2.00) | High | Moderate | E02, E19 |
| 13 | EVSE-Internal ↔ eMSP/External | B | Abuse of payment-terminal or settlement linkage | Moderate (3.00) | High | Moderate | E16, E17 |
| 14 | EVCC ↔ Utility/Grid | B | Manipulated vehicle-side grid-linkage data | Low (2.25) | High | Moderate | E07, E08, E15 |
| 15 | EV-Internal ↔ PKI | B | Abuse of a vehicle security-module-to-PKI path | Low (2.25) | High | Moderate | E03, E18 |
| 16 | EV-Internal ↔ Utility/Grid | B | Manipulated vehicle-internal power-state or DER data | Very Low (1.25) | High | Low | E01, E15 |
| 17 | SECC ↔ Utility/Grid | B | Manipulated SECC-based grid-linkage signal | Very Low (1.25) | High | Low | E03, E07 |
| 18 | eMSP/External ↔ Utility/Grid | B | Manipulated operator-to-grid operational data | Low (2.00) | Moderate | Low | E12, E16 |
| 19 | Utility/Grid ↔ PKI | B | Confusion or compromise across grid-side and V2G trust infrastructures | Low (2.00) | High | Moderate | E13, E20 |

## 6. Summary and decision rule

| Overall risk | Count | Paths |
|---|---:|---|
| High | 4 | CSMS↔Utility/Grid; EVSE/CS↔Utility/Grid; SECC↔CSMS; EVSE/CS↔Wireless |
| Moderate | 12 | IDs 3, 4, 7–15, and 19 |
| Low | 3 | IDs 16–18 |

The four High rows are selected as the A1–A4 anchor paths. The remaining 15
paths receive a design-level archetype mapping only; the risk assessment does
not claim that their traffic characteristics were independently simulated.

## 7. Reproduction checks

For each CSV row, a reviewer can reproduce the output with the following
pseudocode:

```text
likelihood_mean = mean(exposure, feasibility, prevalence, evidence)
likelihood = band(likelihood_mean)
impact_score = max(confidentiality, integrity, availability_grid, impact_scope)
impact = label(impact_score)
overall_risk = MATRIX[likelihood][impact]
```

The score rationale and external evidence keys are row-level fields, so a
reviewer can challenge an individual factor without reconstructing the whole
table.
