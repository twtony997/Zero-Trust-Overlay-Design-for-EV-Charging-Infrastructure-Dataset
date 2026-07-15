from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

OBJECTIVES = [
    "AuthN",
    "AuthZ",
    "Confidentiality",
    "Integrity",
    "Availability",
    "Logging",
    "Revocation",
    "Update",
    "Resilience",
]

PATH_TO_EDGE_KEY = {
    "EVCC <-> SECC": "EVCC|SECC",
    "EVSE/CS <-> CSMS": "EVSE|CSMS",
    "SECC <-> PKI": "PKI|SECC",
    "EVCC <-> PKI": "EVCC|PKI",
    "eMSP/External <-> PKI": "PKI|eMSP",
    "EV-Internal <-> eMSP/External": "EV-Internal|eMSP",
    "EVCC <-> Wireless": "EVCC|Wireless",
    "EVCC <-> CSMS": "CSMS|EVCC",
    "EVCC <-> eMSP/External": "EVCC|eMSP",
    "SECC <-> eMSP/External": "SECC|eMSP",
    "EV-Internal <-> EVSE/CS": "EV-Internal|EVSE",
    "EV-Internal <-> CSMS": "CSMS|EV-Internal",
}


def item(ids: str, mode: str, rationale: str) -> dict[str, str]:
    return {"ids": ids, "mode": mode, "rationale": rationale}


# Positive decisions only. Every omitted path/objective combination is coded 0.
# Multiple IDs are semicolon-separated and are validated on the same Edge_Key.
EVIDENCE = {
    ("EVCC <-> SECC", "AuthN"): item(
        "V2G20-1235; V2G20-065",
        "Direct mechanism",
        "ISO 15118-20 requires V2G-CI-TLS on this edge and describes the channel as authenticated; this directly supports endpoint authentication.",
    ),
    ("EVCC <-> SECC", "AuthZ"): item(
        "V2G20-2343",
        "Direct control",
        "The EVCC is prohibited from initiating certificate installation without the required OEM provisioning credential, which is an explicit eligibility gate on the edge.",
    ),
    ("EVCC <-> SECC", "Confidentiality"): item(
        "V2G20-1235; V2G20-065",
        "Direct mechanism",
        "Mandatory V2G-CI-TLS establishes an encrypted EVCC-SECC channel and therefore directly addresses confidentiality.",
    ),
    ("EVCC <-> SECC", "Integrity"): item(
        "V2G20-1235; V2G20-2311",
        "Direct mechanism",
        "Mandatory TLS protects channel integrity, and the XML-signature requirement explicitly provides message and message-part integrity.",
    ),
    ("EVCC <-> SECC", "Availability"): item(
        "V2G20-2134; V2G20-2358",
        "Direct control",
        "Bounded retransmission timeouts and selective repeat retransmission directly support continued communication under loss.",
    ),
    ("EVCC <-> SECC", "Revocation"): item(
        "V2G20-2388; V2G20-2413",
        "Direct control",
        "The edge carries OCSP status information and requires validation of the OCSP responder before accepting certificate status.",
    ),
    ("EVCC <-> SECC", "Resilience"): item(
        "V2G20-2358",
        "Direct control",
        "Selective acknowledgement and retransmission are required specifically to improve packet-loss handling.",
    ),

    ("EVSE/CS <-> CSMS", "AuthN"): item(
        "A00.FR.401",
        "Direct objective",
        "OCPP requires the Charging Station to authenticate to the CSMS using its certificate.",
    ),
    ("EVSE/CS <-> CSMS", "AuthZ"): item(
        "A00.FR.806",
        "Direct control",
        "The CSMS may restrict the functions available to a Charging Station until factory credentials are updated, providing an explicit authorization gate.",
    ),
    ("EVSE/CS <-> CSMS", "Confidentiality"): item(
        "A00.FR.312",
        "Direct mechanism",
        "OCPP requires the Charging Station-CSMS communication channel to be secured with TLS.",
    ),
    ("EVSE/CS <-> CSMS", "Integrity"): item(
        "A00.FR.312",
        "Direct mechanism",
        "The mandatory TLS channel provides cryptographic integrity protection for OCPP traffic.",
    ),
    ("EVSE/CS <-> CSMS", "Availability"): item(
        "A04.FR.02",
        "Direct control",
        "Disconnected Charging Stations must queue security-event notifications for guaranteed delivery to the CSMS.",
    ),
    ("EVSE/CS <-> CSMS", "Logging"): item(
        "A04.FR.04",
        "Direct objective",
        "OCPP requires security events to be stored in a security log.",
    ),
    ("EVSE/CS <-> CSMS", "Revocation"): item(
        "A00.FR.704",
        "Direct objective",
        "The certificate-management server is recommended to track revoked certificates.",
    ),
    ("EVSE/CS <-> CSMS", "Update"): item(
        "L01.FR.09",
        "Direct objective",
        "OCPP requires firmware updates to be digitally signed over the firmware hash to establish authenticity and origin.",
    ),

    ("SECC <-> PKI", "AuthN"): item(
        "V2G20-2451",
        "Direct objective",
        "The SECC must authenticate the OCSP responder certificate before accepting the response.",
    ),
    ("SECC <-> PKI", "Integrity"): item(
        "V2G20-2452",
        "Direct control",
        "The SECC verifies the signature on the OCSP response and rejects the certificate chain if verification fails.",
    ),
    ("SECC <-> PKI", "Revocation"): item(
        "V2G20-2327; V2G20-2452",
        "Direct objective",
        "ISO defines the OCSP signer trust chain and verification of signed certificate-status responses for the SECC.",
    ),

    ("EVCC <-> PKI", "AuthN"): item(
        "V2G20-2340",
        "Direct control",
        "The EVCC must hold a V2G root CA certificate to verify SECC certificates before TLS establishment.",
    ),
    ("EVCC <-> PKI", "Integrity"): item(
        "V2G20-2414",
        "Direct control",
        "The EVCC verifies the signature on each OCSP response and fails certificate validation on mismatch.",
    ),
    ("EVCC <-> PKI", "Revocation"): item(
        "V2G20-2388; V2G20-2413",
        "Direct objective",
        "The EVCC requests and validates OCSP certificate-status evidence on the PKI-facing path.",
    ),

    ("eMSP/External <-> PKI", "AuthN"): item(
        "V2G20-2329",
        "Direct mechanism",
        "Contract certificates must chain to an eMSP or V2G root trust anchor, establishing the identity basis for eMSP credentials.",
    ),
    ("eMSP/External <-> PKI", "Integrity"): item(
        "V2G20-2336; V2G20-2349",
        "Direct control",
        "ISO constrains signing and cross-signing relationships and requires a governed certificate hierarchy.",
    ),
    ("eMSP/External <-> PKI", "Revocation"): item(
        "V2G20-2590",
        "Direct objective",
        "eMSP and contract certificates must contain CRL distribution points and/or authority-information access for status checking.",
    ),

    ("EV-Internal <-> eMSP/External", "AuthN"): item(
        "TM-06",
        "Direct objective",
        "ENISA calls for mutual authentication on remote monitoring and administration interfaces.",
    ),
    ("EV-Internal <-> eMSP/External", "AuthZ"): item(
        "TM-06",
        "Direct objective",
        "The same ENISA control explicitly requires access-control mechanisms on remote interfaces.",
    ),
    ("EV-Internal <-> eMSP/External", "Confidentiality"): item(
        "TM-14",
        "Direct objective",
        "ENISA requires end-to-end confidentiality protection for sensitive data exchanged with external entities.",
    ),
    ("EV-Internal <-> eMSP/External", "Integrity"): item(
        "TM-14",
        "Direct objective",
        "ENISA explicitly requires end-to-end integrity protection for sensitive external communications.",
    ),

    ("EVCC <-> Wireless", "AuthN"): item(
        "V2G20-2254; V2G20-2259",
        "Direct objective",
        "The EVCC validates the wireless server certificate and refuses the wireless connection when authentication fails.",
    ),
    ("EVCC <-> Wireless", "Confidentiality"): item(
        "V2G20-2247",
        "Direct mechanism",
        "The EV WLAN station must use WPA3-Enterprise or WPA2-Enterprise, providing link-layer encryption.",
    ),

    ("EVCC <-> CSMS", "AuthN"): item(
        "V2G20-2257; V2G20-2261",
        "Direct objective",
        "The EVCC and the CSO authentication server are required to authenticate one another with certificates.",
    ),

    ("EVCC <-> eMSP/External", "AuthN"): item(
        "V2G20-1078",
        "Direct mechanism",
        "The EVCC verifies the CertificateInstallationRes signature with the CPS signer certificate chain, authenticating the signed response source.",
    ),
    ("EVCC <-> eMSP/External", "Integrity"): item(
        "V2G20-1078",
        "Direct objective",
        "Signature verification of CertificateInstallationRes directly checks response integrity.",
    ),

    ("SECC <-> eMSP/External", "AuthN"): item(
        "V2G20-2211",
        "Direct control",
        "The SECC checks whether the eMSP named by the EMAID in the ContractCertificate is recognized and returns an explicit warning otherwise.",
    ),

    ("EV-Internal <-> EVSE/CS", "Confidentiality"): item(
        "TM-28",
        "Direct objective",
        "ENISA requires encryption of sensitive, personal, and private data mapped to this communication edge.",
    ),

    ("EV-Internal <-> CSMS", "Confidentiality"): item(
        "TM-28",
        "Direct objective",
        "ENISA requires encryption of sensitive, personal, and private data mapped to this communication edge.",
    ),
}


ZERO_RATIONALE = {
    "AuthN": "No mapped Edge-level requirement directly requires actor or endpoint authentication on this path.",
    "AuthZ": "No mapped Edge-level requirement directly governs permission, privilege, or allowed actions on this path.",
    "Confidentiality": "No mapped Edge-level requirement directly requires protection against disclosure on this path.",
    "Integrity": "No mapped Edge-level requirement directly requires detection or prevention of unauthorized modification on this path.",
    "Availability": "No mapped Edge-level requirement directly requires service or communication availability on this path.",
    "Logging": "No mapped Edge-level requirement directly requires security-event logging or audit records on this path.",
    "Revocation": "No mapped Edge-level requirement directly requires credential or certificate revocation/status handling on this path.",
    "Update": "No mapped Edge-level requirement directly requires secure software, firmware, or credential update handling on this path.",
    "Resilience": "No mapped Edge-level requirement directly requires recovery, failover, or continued safe operation under faults or attack on this path.",
}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_rows(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    edge_rows = read_rows(DATA / "edge_requirements_452.csv")
    edge_index: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in edge_rows:
        edge_index.setdefault((row["Edge_Key"], row["Requirement_ID"]), []).append(row)

    coverage_rows = read_rows(DATA / "active_coverage_9objectives.csv")
    paths = [row["Active edge"] for row in coverage_rows]
    if set(paths) != set(PATH_TO_EDGE_KEY):
        raise ValueError("Active path set does not match PATH_TO_EDGE_KEY")

    evidence_rows: list[dict[str, object]] = []
    for path in paths:
        edge_key = PATH_TO_EDGE_KEY[path]
        for objective in OBJECTIVES:
            evidence = EVIDENCE.get((path, objective))
            if evidence is None:
                evidence_rows.append(
                    {
                        "Path": path,
                        "Objective": objective,
                        "Standard": "",
                        "Source document": "",
                        "Requirement ID": "",
                        "Mapping ID": "",
                        "Coding decision": 0,
                        "Evidence mode": "No qualifying direct evidence",
                        "Rationale": ZERO_RATIONALE[objective],
                    }
                )
                continue

            ids = [value.strip() for value in evidence["ids"].split(";")]
            matched: list[dict[str, str]] = []
            for req_id in ids:
                candidates = edge_index.get((edge_key, req_id), [])
                if not candidates:
                    raise ValueError(f"Missing evidence: {path} / {objective} / {req_id} on {edge_key}")
                matched.append(candidates[0])

            evidence_rows.append(
                {
                    "Path": path,
                    "Objective": objective,
                    "Standard": "; ".join(dict.fromkeys(row["Standard"] for row in matched)),
                    "Source document": "; ".join(dict.fromkeys(row["Source_Document"] for row in matched)),
                    "Requirement ID": "; ".join(ids),
                    "Mapping ID": "; ".join(row["Mapping_ID"] for row in matched),
                    "Coding decision": 1,
                    "Evidence mode": evidence["mode"],
                    "Rationale": evidence["rationale"],
                }
            )

    if len(evidence_rows) != len(paths) * len(OBJECTIVES):
        raise AssertionError("Evidence table must contain exactly 12 x 9 rows")

    write_rows(
        DATA / "edge_objective_evidence_mapping.csv",
        [
            "Path",
            "Objective",
            "Standard",
            "Source document",
            "Requirement ID",
            "Mapping ID",
            "Coding decision",
            "Evidence mode",
            "Rationale",
        ],
        evidence_rows,
    )

    decisions = {
        (row["Path"], row["Objective"]): int(row["Coding decision"])
        for row in evidence_rows
    }
    audited_coverage: list[dict[str, object]] = []
    for source in coverage_rows:
        path = source["Active edge"]
        row: dict[str, object] = {"Active edge": path}
        for objective in OBJECTIVES:
            row[objective] = decisions[(path, objective)]
        objective_count = sum(int(row[objective]) for objective in OBJECTIVES)
        core = all(int(row[objective]) == 1 for objective in ["AuthN", "AuthZ", "Confidentiality", "Integrity"])
        row["objectives"] = objective_count
        row["Core covered"] = "Yes" if core else "No"
        row["Class"] = "Fully Covered" if objective_count >= 6 and core else "Partially Covered"
        audited_coverage.append(row)

    write_rows(
        DATA / "active_coverage_9objectives.csv",
        ["Active edge", *OBJECTIVES, "objectives", "Core covered", "Class"],
        audited_coverage,
    )

    positives = sum(int(row["Coding decision"]) for row in evidence_rows)
    print(f"Wrote {len(evidence_rows)} objective decisions ({positives} positive, {len(evidence_rows)-positives} zero).")


if __name__ == "__main__":
    main()
