# ADR-0009: Project Open-Source License (GNU General Public License v3.0)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** Project Author / Maintainers
* **Consulted:** Open-source legal and governance review
* **Informed:** All contributors

## Context

`sito` is designed as a modern, high-performance, self-hosted filtering DNS server. Before publishing the repository and accepting external contributions, the project must establish its permanent open-source license. Changing a project license after accepting contributions from multiple independent authors requires obtaining consent from every contributor or executing complex relicensing procedures.

Key considerations:
1. **Copyleft Protection:** Guaranteeing that downstream distributors or vendors embedding `sito` into routers, appliances, or commercial hardware cannot privatize improvements or withhold source code modifications from the community.
2. **Community Alignment:** AdGuard Home, whose rule syntax, feature set, and self-hosting philosophy serve as a major inspiration and ecosystem baseline, is licensed under **GNU General Public License v3.0 (GPL-3.0)**.
3. **Network/SaaS Use vs. Broad Adoption:** Evaluating whether the Affero GPL (AGPL-3.0) is necessary to close the "network service / SaaS loophole" versus the risk of deterring corporate homelab users, university labs, and enterprise homelab contributors due to broad corporate anti-AGPL policies.

## Decision

We select the **GNU General Public License v3.0 (`GPL-3.0-only`)** as the official open-source license for `sito`.

Governance policies:
- All source files, crates in the workspace, and generated binaries are licensed under `GPL-3.0-only`.
- External contributions will be accepted under the **Developer Certificate of Origin (DCO)** via `Signed-off-by` git commit lines (`git commit -s`), avoiding the legal friction of a proprietary Contributor License Agreement (CLA).
- Dependency policy (`deny.toml`) permits standard permissive licenses (MIT, Apache-2.0, BSD, MPL-2.0, ISC, CC0-1.0) and GPL-compatible components.

## Consequences

### Positive
- Strong copyleft guarantees that improvements, security patches, and ports made by third parties must remain open-source.
- Perfect philosophical and legal alignment with AdGuard Home and the broader self-hosted privacy software ecosystem.
- Avoids the enterprise and homelab contributor friction frequently associated with AGPL-3.0, which many enterprise open-source policies ban categorically.
- Protects users against patent retaliation via GPL-3.0's explicit patent grant clauses.

### Negative
- Cloud providers or managed service operators could hypothetically host `sito` as a managed remote DNS SaaS endpoint without distributing modified source code if they never distribute the binary (the traditional ASP loophole). Given `sito`'s focus on local on-premise/homelab DNS filtering, this is an acceptable tradeoff.

### Neutral / Operational
- `LICENSE` file containing the official GNU GPL-3.0 text is placed at the repository root.
- Every workspace crate manifest specifies `license.workspace = true` pointing to `GPL-3.0-only`.

## Alternatives Considered

### Alternative 1: GNU Affero General Public License v3.0 (AGPL-3.0)
- **Pros:** Closes the SaaS loophole by requiring remote network operators who modify the code to make source available over the network.
- **Cons:** Many corporate developers, homelabbers with employer-mandated open source policies, and enterprise contributors are explicitly prohibited by internal legal policies from touching or contributing to AGPL projects.
- **Why not chosen:** Maximizing community contributions and adoption in the homelab/self-hosted ecosystem is prioritized over SaaS defense.

### Alternative 2: Permissive Licenses (MIT / Apache-2.0)
- **Pros:** Maximum adoption freedom; allows embedding in proprietary commercial router firmwares without source sharing.
- **Cons:** Commercial hardware vendors could take the core engine, add proprietary optimizations or web panels, and distribute closed-source appliances without giving anything back to the project.
- **Why not chosen:** Undermines the copyleft ethos of an independent, privacy-focused community DNS project.
