# Limitations

- OUI/vendor lookup is a small offline best-effort hint table, not a complete or authoritative IEEE OUI database.
- MAC discovery depends on local ARP visibility, OS behavior, and network segment accessibility.
- Hostname discovery is best-effort and depends on reverse DNS/local name resolution.
- Port-based role classification is heuristic and is not real service fingerprinting.
- Attention score is not a CVE score and not a full vulnerability assessment.
- TCP-only discovery may miss live hosts that do not expose any of the scanned TCP ports.
- The device passport remains mostly IP-centric; confidence-based matching is currently used for scan-to-scan analysis, not as a full stable device identity model.
