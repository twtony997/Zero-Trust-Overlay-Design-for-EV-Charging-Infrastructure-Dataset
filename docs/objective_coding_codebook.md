# Nine-objective Coverage Coding Codebook

This codebook defines how `data/active_coverage_9objectives.csv` is derived from`data/edge_requirements_452.csv`. 
The auditable long-form decisions are in`data/edge_objective_evidence_mapping.csv` (12 Active paths × 9 objectives = 108 rows). 
The compact coverage table is a pivot of the `Coding decision` column, not an independently edited result.

## Unit of analysis and decision rule

The unit of analysis is one Active path × security objective pair. A
decision is coded `1` only when at least one requirement already mapped to that
Edge does one of the following:

1. explicitly names and requires the objective (`Direct objective` or `Direct control`); or
2. requires a mechanism whose stated purpose on the same path necessarily supplies the objective (`Direct mechanism`), such as mandatory TLS for confidentiality and integrity.

Otherwise the decision is `0`. Mere occurrence of a keyword, a section heading, a protocol reference, a notation example, or an implementation possibility does not qualify. A requirement mapped only at Node, Zone, organizational-policy, or IEC cross-cutting level does not make an Edge-level objective positive.

Normative `shall` requirements and source-level recommendations (`should`, `may`, or guideline imperatives) are retained because the study analyzes both standards and guidelines. 
The exact modality remains visible in the released source text and Requirement ID; the binary indicator records presence, not strength.

## Objective definitions

| Objective | Code `1` when a mapped Edge requirement directly addresses … |
|---|---|
| AuthN | verification of an actor, endpoint, device, server, or credential holder |
| AuthZ | permission, privilege, eligibility, allowed functions, or allowed actions |
| Confidentiality | prevention of unauthorized disclosure in transit on the path |
| Integrity | detection or prevention of unauthorized message or data modification |
| Availability | continued delivery or communication service within an operational bound |
| Logging | security-event, diagnostic, or audit-record creation/retention |
| Revocation | revocation, certificate-status checking, CRL, or OCSP handling |
| Update | secure software, firmware, certificate, or credential update on the path |
| Resilience | recovery, failover, loss handling, or continued safe operation under fault/attack |

`Availability` and `Resilience` are deliberately distinct: availability covers
the service outcome, whereas resilience requires a recovery or fault-handling
mechanism. A requirement can support both when its text directly supports both
decisions.

## Multiple-objective mapping

One requirement may be repeated across several objective rows when its text or
required mechanism directly supports each objective. For example, mandatory
TLS can support AuthN, confidentiality, and integrity, and a packet-loss
handling requirement can support both availability and resilience. Repeating
the Requirement ID in the long-form file makes these one-to-many decisions
explicit instead of hiding them in a single binary row.

## Zero decisions

All zero decisions are retained as rows. Their `Standard`, `Source document`,
`Requirement ID`, and `Mapping ID` fields are blank, and the rationale states
that no qualifying Edge-level requirement was found for the objective. This is
an absence finding limited to the five analyzed sources; it does not assert
that no applicable control exists elsewhere.

## Audit correction made during evidence reconstruction

Reconstruction of the evidence table exposed five unsupported or inconsistent
cells in the earlier compact table. The following corrections preserve the
overall classification result (2 Fully Covered and 10 Partially Covered):

| Path | Objective | Earlier | Audited | Reason |
|---|---:|---:|---:|---|
| EV-Internal ↔ eMSP/External | Integrity | 0 | 1 | ENISA TM-14 explicitly requires end-to-end integrity |
| EVCC ↔ CSMS | Integrity | 1 | 0 | the mapped items authenticate the CSO server, but none directly requires message integrity on this Edge |
| SECC ↔ eMSP/External | Integrity | 1 | 0 | the mapped item recognizes the eMSP in a ContractCertificate, but does not directly require message-integrity verification on this Edge |
| EV-Internal ↔ EVSE/CS | AuthN | 1 | 0 | TM-28 addresses encryption/authenticated encryption, not actor or endpoint authentication |
| EV-Internal ↔ CSMS | AuthN | 1 | 0 | TM-28 addresses encryption/authenticated encryption, not actor or endpoint authentication |

The net number of positive cells changes because one newly supported cell and
four unsupported cells are corrected. All twelve Active paths still have at
least one positive objective, and the two dominant paths still satisfy the
Fully Covered rule.

## Regeneration

Run:

```bash
python scripts/build_objective_evidence.py
```

The script validates every positive Requirement ID against the expected
`Edge_Key`, writes the 108-row evidence table, and derives the compact coverage
table from those decisions.
