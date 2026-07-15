# ZTA Overlay Design for the Four Anchor Paths

Four-layer design for each anchor path, plus the common policy model. The paper (Section 4.4) gives the consolidated archetype table; all paths use the enforcement procedure of Algorithm 2.

## Design targets

| Path | Risk | Gap type | Main security gap | ZTA design goal |
|---|---|---|---|---|
| CSMS ↔ Utility/Grid (A1 anchor) | High | Gap-A | No authentication, integrity, or authorization requirements for grid-linked commands | Verify the sender of grid signals, validate DR-command integrity, restrict allowed command scope |
| EVSE/CS ↔ Utility/Grid (A2 anchor) | High | Gap-A | No EVSE-level grid-linkage / DER control requirements | EVSE device authentication, grid-command authorization, charging-load control limits |
| SECC ↔ CSMS (A3 anchor) | High | Gap-B | Implementation-level gap between the ISO 15118 V2G boundary and the OCPP operational boundary | Charger-internal inter-process authentication, allowed-message restriction, internal control-path auditing |
| EVSE/CS ↔ Wireless (A4 anchor) | High | Gap-B | No medium-specific requirements for wireless backhaul / field access networks | Wireless access-device authentication, TLS enforcement, fixed CSMS connection target, session anomaly detection |

## NIST SP 800-207 component mapping

| ZTA component | Function | EV charging infrastructure mapping | Applied paths |
|---|---|---|---|
| Policy Engine (PE) | Allow/deny decision based on subject, resource, session, environment attributes | CSMS policy engine, EVSE local policy engine, charger-internal lightweight policy module | All four |
| Policy Administrator (PA) | Converts PE decisions into session tokens, policy commands, authentication state | CSMS session manager, certificate-management module, local security module | A1, A3, A4 |
| Policy Enforcement Point (PEP) | Allows/blocks/logs communication requests | CSMS API Gateway, EVSE Gateway, SECC–OCPP IPC layer, wireless modem / network access layer | All four |
| PIP Adapter | Collects and normalizes telemetry for policy decisions | OCPP state, certificate status, TLS session info, grid command type, wireless access state | All four |

## A1 anchor — CSMS ↔ Utility/Grid

PEP: CSMS API Gateway or grid-linkage gateway. PE: CSMS policy engine. PIP collects Utility/Grid subject identifier, certificate status, command type, target charger scope, load-control limits, event validity time.

| Layer | Component | Detailed design | Verification variables |
|---|---|---|---|
| Authentication | Utility/Grid subject authentication | Certificate-based mutual authentication with grid-linked subjects; block grid commands from unregistered subjects | Auth latency; blocking of unregistered subjects |
| Access control | Grid-command authorization | PE decides based on subject, command type, target charger scope, load-control limit | Policy-decision latency; allow/deny outcome |
| Integrity | Command integrity & anti-replay | Verify signature, nonce, timestamp on DR events / grid control commands; block replayed commands | Forged-command block rate; replay block rate |
| Monitoring | Grid-event audit & anomaly alerting | Audit-log all grid-linked commands; alert when commands-per-interval or load swing exceeds thresholds | Alert latency; audit-log delay |

## A2 anchor — EVSE/CS ↔ Utility/Grid

PEP: EVSE local controller or field gateway. PIP collects EVSE state, active session count, power usage, load-control capability range, grid command content.

| Layer | Component | Detailed design | Verification variables |
|---|---|---|---|
| Authentication | EVSE device authentication | Issue device certificates to EVSE/CS; verify device state and certificate validity before accepting grid commands | Certificate-verification latency; blocking of unregistered EVSE |
| Access control | EVSE-level least-privilege policy | PE decides based on EVSE ID, allowed power range, site policy, command type | Policy-decision latency; blocking of over-limit commands |
| Integrity | Grid control-command verification | Verify signatures and time information of load-control, DER-control, and charging-profile-change commands | Forged-command block rate; anti-replay |
| Monitoring | EVSE grid-linkage audit | Store EVSE-level grid commands and load-control results in local and backend audit logs | Logging delay; anomalous-command alerting |

## A3 anchor — SECC ↔ CSMS

PEP: internal IPC layer between the SECC process and the OCPP client / CSMS-linkage module. PE: charger-internal lightweight policy module. PA issues session tokens at boot and manages inter-process privileges. PIP collects SECC state, OCPP message type, charging-session state, firmware-integrity state.

| Layer | Component | Detailed design | Verification variables |
|---|---|---|---|
| Authentication | Internal IPC token authentication | Apply session-token or HMAC-based authentication to internal message exchange between SECC and the OCPP client | Token-verification latency; blocking of unauthorized internal messages |
| Access control | OCPP message-type restriction | PEP passes only allow-listed message types; blocks OCPP commands that must not originate at the SECC boundary | Allow-list decision latency; unauthorized-command block rate |
| Integrity | Firmware & internal-state integrity | Verify firmware signature at boot; periodically check integrity of key processes / configuration at runtime | Firmware-verification latency; integrity-failure detection |
| Monitoring | Internal-path anomaly detection | Detect SECC→OCPP message-frequency anomalies, abnormal message types, session-state mismatch; forward logs to CSMS | Anomaly-detection time; log-forwarding delay |

## A4 anchor — EVSE/CS ↔ Wireless

PEP: wireless modem, eSIM/iSIM access layer, OCPP WSS connection layer. PE: EVSE/CS local policy engine or CSMS-side access policy engine. PIP collects SIM identifier, APN info, TLS version, certificate fingerprint, CSMS FQDN, Cell-ID change frequency, OCPP session state.

| Layer | Component | Detailed design | Verification variables |
|---|---|---|---|
| Authentication | Wireless access-device authentication | Allow only registered EVSE/CS via eSIM/iSIM, device certificates, private APN, or WPA3-Enterprise | Wireless-auth latency; blocking of unregistered access |
| Access control | Fixed CSMS connection target | Pin allowed CSMS FQDN, certificate fingerprint, port, protocol by policy; block unregistered targets | Pinning-verification latency; unauthorized-FQDN block |
| Integrity | TLS enforcement & session binding | Enforce allowed TLS version and certificate-verification conditions on the OCPP WSS connection; bind TLS session to OCPP session | TLS-downgrade block rate; session-binding failure detection |
| Monitoring | Wireless-session anomaly detection | Detect abnormal sessions from Cell-ID changes, reconnect frequency, TLS errors, OCPP session-restart patterns | Anomalous-session detection time; Fail-Secure transition |

## Common policy model (all archetypes)

| Policy element | Content | Applied paths | Modeling variables |
|---|---|---|---|
| Least privilege | Each subject operates only within predefined message types, command scope, power range, session purpose; default is Deny-All | All four | Allowed-message set; block outcomes; policy-decision latency |
| Continuous verification | Re-verify certificate, token, TLS, and device state during the session, not only at establishment | A1, A2, A4 | Re-verification interval/latency; block on failure |
| Micro-segmentation | CSMS, EVSE/CS, SECC, and grid-linkage modules are governed as separate policy segments | All four | Per-segment enforcement; blocking of unauthorized boundary crossing |
| Audit logging | Append-only record of PE decisions, PA token issuance, PEP blocks, session re-verification, and failure events | All four | Logging delay; audit-event count |
| Fail-Secure | On PE/PA/PEP or policy-decision failure, default to connection denial; require re-authentication after recovery | All four | Failure-detection time; Fail-Secure transition |

Extended (◐) paths inherit the layer structure and controls of their archetype anchor; only the PEP placement instance and the PIP attribute set are specialized per path.
