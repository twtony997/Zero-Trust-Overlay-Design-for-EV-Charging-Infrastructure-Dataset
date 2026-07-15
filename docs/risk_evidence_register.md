# External Evidence Register for the 19-path Risk Assessment

The `External_Evidence` column in `data/risk_assessment_19paths.csv` uses the
keys below. A source supports the existence, exposure, attack feasibility, or
potential impact of a scenario; it is not treated as proof of a universal
likelihood or impact score. Scores remain bounded judgments under the published
operational definitions.

| Key | Source and locator | Evidence role |
|---|---|---|
| E01 | NIST, *Cybersecurity Framework Profile for Electric Vehicle Extreme Fast Charging Infrastructure*, NIST IR 8473, 2023, doi: `10.6028/NIST.IR.8473` (especially AM-3 and the reference architecture) | EV/XFC assets, grid actors, interfaces, and cybersecurity context |
| E02 | Open Charge Alliance, *OCPP 2.0.1*, 2021, especially Part 2 Appendix A, A02/A03/A04, the Device Model, and certificate-management use cases | Charging Station-CSMS controls, PKI brokering, event logging, and the medium-agnostic OCPP boundary |
| E03 | ISO 15118-20:2022 and ISO 15118-1:2019, especially the V2G actor model, certificate architecture, and bidirectional-power-transfer use cases | EVCC-SECC-PKI trust model and the ISO/OCPP boundary |
| E04 | ENISA, *Good Practices for Security of Smart Cars*, 2019, doi: `10.2824/17802`, especially Annex A and TM-06-TM-15 | telematics, external interfaces, in-vehicle communications, wireless exposure, and recommended controls |
| E05 | J. Johnson et al., “Review of Electric Vehicle Charger Cybersecurity Vulnerabilities, Potential Impacts, and Defenses,” *Energies*, 15(11), 3931, 2022, doi: `10.3390/en15113931` | charger attack surface, remote interfaces, impacts, and defenses |
| E06 | S. Hamdare et al., “Cybersecurity Risk Analysis of Electric Vehicles Charging Stations,” *Sensors*, 23(15), 6716, 2023, doi: `10.3390/s23156716` | EVCS threat scenarios and risk context |
| E07 | S. Acharya et al., “Cybersecurity of Smart Electric Vehicle Charging: A Power Grid Perspective,” *IEEE Access*, 8, 214434-214453, 2020, doi: `10.1109/ACCESS.2020.3041074` | charging-to-grid attack paths and grid impacts |
| E08 | S. Acharya, Y. Dvorkin, and R. Karri, “Public Plug-in Electric Vehicles + Grid Data: Is a New Cyberattack Vector Viable?,” *IEEE Transactions on Smart Grid*, 11(6), 5099-5113, 2020, doi: `10.1109/TSG.2020.2994177` | feasibility and impact of EV/grid data manipulation |
| E09 | F. Wei and X. Lin, “Cyber-Physical Attack Launched From EVSE Botnet,” *IEEE Transactions on Power Systems*, 39(2), 3603-3614, 2024, doi: `10.1109/TPWRS.2023.3279323` | fleet-scale EVSE compromise and power-system impact |
| E10 | J. Antoun et al., “A Detailed Security Assessment of the EV Charging Ecosystem,” *IEEE Network*, 34(3), 200-207, 2020, doi: `10.1109/MNET.001.1900348` | component and interface attack surface across the EV-charging ecosystem |
| E11 | K. Sarieddine et al., “EV Charging Infrastructure Discovery to Contextualize Its Deployment Security,” *IEEE Transactions on Network and Service Management*, 21(1), 1287-1301, 2024, doi: `10.1109/TNSM.2023.3318406` | observable deployment exposure of charging-management infrastructure |
| E12 | OpenADR Alliance, *OpenADR 2.0b Profile Specification*, especially the VTN/VEN model and demand-response event exchange | utility-to-operator demand-response roles and command flow |
| E13 | IEEE 2030.5-2018, *Smart Energy Profile Application Protocol*, including security and DER-function clauses | aggregator/DER communication, utility-facing control, and PKI use |
| E14 | IEEE 1547-2018, *Interconnection and Interoperability of Distributed Energy Resources with Associated Electric Power Systems Interfaces*, including Annex B | grid-facing DER functionality of internal power components |
| E15 | SAE J2836/3, *Use Cases for Plug-In Vehicle Communications as a Distributed Energy Resource* | vehicle-as-DER and bidirectional grid-service use cases |
| E16 | EVRoaming Foundation, *Open Charge Point Interface (OCPI) 2.2.1*, especially roles and smart-charging modules | eMSP/roaming/payment roles and delegated smart-charging exchange |
| E17 | PCI Security Standards Council, *Payment Card Industry Data Security Standard (PCI DSS) v4.0.1* | protection expectations for payment-terminal and account-data paths |
| E18 | CharIN, *Plug & Charge Guide*, v1.2, especially the V2G PKI and certificate-provisioning sections | vehicle, OEM, eMSP, and PKI trust relationships |
| E19 | Physikalisch-Technische Bundesanstalt, PTB-A 50.7 and associated German legal-metrology guidance for electricity meters | signed/secured metering components and device-specific trust anchors |
| E20 | Sandia National Laboratories, SAND2019-1490, California Smart Inverter Profile / IEEE 2030.5 PKI guidance | grid-side certificate infrastructure distinct from the V2G PKI |

## Method source

The risk workflow is adapted from R. S. Ross, *Guide for Conducting Risk
Assessments*, NIST SP 800-30 Rev. 1, 2012, doi:
`10.6028/NIST.SP.800-30r1`. NIST SP 800-30 does not prescribe the custom 5×5
matrix in this repository; the matrix and score thresholds are study-specific
and are therefore published in full in `docs/risk_assessment_19paths.md`.
