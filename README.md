# Communication-Path Security Gaps in EV Charging Standards: A Zero Trust Overlay and Simulation-Based Validation

## Overview

The study maps security requirements from five standards - NIST IR 8473, ISO 15118-20, OCPP 2.0.1, ENISA Good Practices for Security of Smart Cars, and IEC 62443-3-3, onto a Zone–Node–Edge model of EV charging infrastructure (10 entities, 39 candidate communication paths), classifies each path, and designs a Zero Trust overlay for the high-risk gaps.

- 1,559 mapped requirement instances (941 Node/Zone + 452 Edge + 115 organizational + 51 IEC cross-cutting)
- 39 candidate paths classified as Active (12) / Gap-A (4) / Gap-B (15) / Non-Applicable (8) → 19 gap paths
- NIST SP 800-30 (5×5) risk assessment → 4 high-risk anchor paths
- NIST SP 800-207 Zero Trust overlay, generalized into four archetypes (A1-A4) covering all 19 gaps (4 anchors with detailed design; generic enforcement mechanisms simulated; 15 extended paths inherit the design archetype)
- SimPy Monte Carlo simulation, 100 runs (seeds 0-99), scenarios S1–S5 with baselines B0–B3

The paper reports summary tables; the full per-requirement and per-path data are here.

## Repository structure

```
.
├── README.md
├── LICENSE
├── requirements.txt
├── data/
│   ├── requirement_master_1559.csv            # 1,559 mapped instances with source text
│   ├── node_requirements_941.csv              # Node/Zone-level requirements
│   ├── edge_requirements_452.csv              # Edge-level requirements, per path
│   ├── org_policies_115.csv                   # organizational-policy items
│   ├── iec_crosscutting_51.csv                # IEC 62443-3-3 cross-cutting controls
│   ├── path_classification_39.csv             # 39-path classification, rationale, Gap-B evidence level, ZTA archetype/role
│   ├── all_45_entity_pairs.csv                # 45-pair enumeration + 6 intra-group exclusions
│   ├── active_coverage_9objectives.csv        # 9-objective coverage of the 12 Active paths
│   ├── edge_objective_evidence_mapping.csv    # 108 auditable path-objective decisions with Requirement IDs
│   ├── risk_assessment_19paths.csv             # row-level likelihood/impact subscores and matrix result
│   ├── baseline_illustrative_block_rates.csv  # illustrative baseline block rates (sensitivity only)
│   ├── node_summary.csv / edge_summary.csv
│   └── subentity_detail.csv
├── simulation/
│   ├── simulation_code.py                     # SimPy DES, n=100, S1–S5 + B0–B3
│   └── results/                               # summary, per-seed CSV, and figures
├── scripts/
│   └── build_objective_evidence.py            # validates IDs and derives the compact coverage table
└── docs/
    ├── risk_assessment_19paths.md             # full 19-path SP 800-30 risk table
    ├── risk_evidence_register.md               # external evidence keys used by the risk rows
    ├── objective_coding_codebook.md            # objective definitions and binary coding rules
    ├── zta_design_anchor_paths.md             # per-anchor four-layer ZTA design + common policy model
    └── parameter_provenance_sensitivity.md    # simulation parameter provenance + sensitivity
```

## Data notes

- Counts: 1,559 = 941 + 452 + 115 + 51. Per standard: NIST IR 8473 = 212, ISO 15118-20 = 972, OCPP 2.0.1 = 230, ENISA = 94, IEC 62443-3-3 = 51. These are mapping counts; a requirement mapped to k assets contributes k instances, and 1,296 unique requirements underlie the 1,559 instances.
- Two EVCC↔SECC entries (`V2G20-1000`, `V2G20-000`) are ISO 15118-20 notation examples. They are kept in the counts for reproducibility but are not treated as normative requirements (disclosed in the paper).
- S5 draws one response delay per injected PEP failure from the assumed local-watchdog distribution (`PEP_DETECT_*`), not from the OCPP `HeartbeatInterval` (60 s). It is a model-input sensitivity result, not an implementation benchmark. See `simulation/simulation_code.py` and `docs/parameter_provenance_sensitivity.md`.
- `path_classification_39.csv` matches the paper's classification (Active 12 / Gap-A 4 / Gap-B 15 / Non-Applicable 8). The `ZTA_Archetype` (A1–A4) and `ZTA_Role` (anchor / extended) columns encode the archetype mapping; 19 gaps = 4 anchors + 15 extended.
- `active_coverage_9objectives.csv` is derived from the 108-row evidence table. The coding audit corrected five cells while preserving the headline result of 2 Fully Covered and 10 Partially Covered paths; see `docs/objective_coding_codebook.md`.

## Reproducing the simulation

```bash
pip install -r requirements.txt
python simulation/simulation_code.py               
```

Runs are deterministic per seed (0–99). Expected aggregate results (n = 100):

| Scenario | Metric | Result |
|---|---|---|
| S1 Normal session | ZTA overhead | 175.15 ms (0.584% of OCPP MessageTimeout) |
| S4 TLS downgrade | Wireless handshake delay | 250 ms vs 400 ms (−37.5%, TLS 1.3 vs legacy) |
| S5 PEP failure | sampled local-watchdog response delay | 100.35 ms (assumed N(100 ms, 15 ms); one sample/run) |

S1 overhead is the primary quantitative model output. S5 recovers the behavior of its assumed watchdog-delay input distribution, and S2–S4 are illustrative policy outcomes rather than empirical attack-blocking measurements. The simulation evaluates generic enforcement mechanisms represented by the anchor designs; it does not independently model the traffic characteristics of all four anchors. The run also reports EVSE-count sensitivity (50/100/500/1000) and a concurrent-burst OCSP queueing stress test; see `docs/parameter_provenance_sensitivity.md`.

## License

Code (`simulation/`): MIT - see `LICENSE`.
The dataset (`data/`) and documentation (`docs/`) are released for academic reference alongside the paper; no separate open data license is granted, so all rights are reserved for those files. For reuse beyond the paper, please contact the authors.
