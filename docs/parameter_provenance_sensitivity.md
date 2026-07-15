# Simulation Parameter Provenance and Sensitivity

Provenance of the simulation input parameters and the two sensitivity analyses. The delay values are model inputs chosen to compare the relative effect of the ZTA overlay; they do not represent measured performance of commercial equipment. S1 and S5 therefore report behavior under the assumed distributions, not benchmark measurements.

## Parameter provenance

| Parameter | Value | Category | Basis |
|---|---|---|---|
| Simulation horizon | 7,200 s (2 h) | Model setting | Window long enough for stable event counts across all five scenarios |
| Number of EVSE | 50 (default) | Model setting | Mid-size site cluster; varied to 100 / 500 / 1000 in the fleet-size sensitivity |
| Monte Carlo runs | 100 (seeds 0–99) | Statistical design | Bootstrap 95% confidence intervals; deterministic per seed |
| HeartbeatInterval | 60 s | Protocol setting | OCPP 2.0.1 application-layer keepalive between charger and CSMS; does not drive PEP failure detection |
| MessageTimeout | 30 s | Protocol setting | OCPP 2.0.1 operational budget against which S1 overhead is reported (0.584%) |
| mTLS handshake delay | N(150 ms, 30 ms) | Model assumption | TLS 1.3 mutual-authentication handshake scale |
| PE decision delay | Exp(mean 5 ms) | Model assumption | Lightweight policy evaluation |
| OCSP check delay | N(20 ms, 5 ms) | Model assumption | Certificate status-check round trip |
| OCSP responder capacity | 8 concurrent | Model setting | Shared CSMS OCSP responder; drives the concurrent-burst stress test |
| Attack inter-arrival (S2/S3/S4) | Exp(120 / 90 / 180 s) | Model assumption | Affects sample counts, not blocking logic |
| PEP failure time (S5) | 3,600 s | Model setting | Mid-horizon failure injection |
| Local-watchdog response delay (S5) | N(100 ms, 15 ms), floor 20 ms | Model assumption | One delay draw is recorded for the one injected PEP failure in each seeded run; separate from the 60 s OCPP heartbeat |
| S4 wireless handshake (legacy / TLS 1.3) | N(400 ms, 80 ms) / N(250 ms, 50 ms) | Model assumption | Downgrade-permissive vs TLS 1.3-enforced session establishment |

The attack processes now implement exactly the stated exponential distributions: each next-arrival delay is sampled as `Exp(mean=interval)`. The earlier expression `interval + Exp(interval × 0.25)` has been removed.

S1 is scoped to session establishment (mTLS + policy evaluation + OCSP). The earlier unused 0.5 ms per-message allowlist constant has been removed rather than arbitrarily adding one message-level check to a session-level metric.

No 30 s replay window or ±5 s timestamp tolerance is implemented. S2 samples illustrative policy outcomes from the declared `BLOCK_PROB` assumptions; the paper no longer describes a replay-window timing model.

## Sensitivity analyses

Both are part of the main run and are written to `simulation/results/simulation_summary.json`. Seed-level values for all scenarios are written to `simulation/results/per_seed_results.csv`.

Fleet size (EVSE count). S1 overhead is evaluated at 50 / 100 / 500 / 1000 EVSEs (`EVSE_sensitivity`). Overhead grows only mildly with fleet size — the shared OCSP responder is the only contended resource — and stays within the MessageTimeout budget across the range.

Concurrent-burst OCSP queueing. As a worst case, 50% of the fleet re-establishes sessions simultaneously and the OCSP responder queueing delay (mean, p95) is measured at each fleet size (`burst_ocsp_wait`), isolating the shared responder under burst load.

Within these ranges the overhead stays a small fraction of the MessageTimeout. Under the assumed local-watchdog delay distribution, the 100 one-failure-per-run samples average 100.35 ms (bootstrap 95% CI 97.43-103.18 ms). This recovers an input-distribution property; it is not evidence that an implemented watchdog detects failures in 100 ms.

## Scope of the anchor-path simulation

The simulation evaluates generic enforcement mechanisms represented by the four anchor-path designs. It does not implement independent traffic generators, protocol state machines, or empirical workload parameters for A1-A4. Consequently, the simulation supports a mechanism-level feasibility claim only; it does not independently validate the traffic characteristics of all four anchor paths or of the 15 extended paths.
