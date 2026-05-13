# scan-compromised.sh

> **TeamPCP / Mini Shai-Hulud supply chain scanner**
> Checks your entire project tree for all known IOCs from the May 11, 2026 npm + PyPI attack.

---

## What it does

The script recursively scans every project in the target directory and checks for **11 TeamPCP TTPs** (Tactics, Techniques, and Procedures):

| Check | What it detects |
|---|---|
| **TTP-01** npm lockfiles | 170+ compromised package versions across 14 scopes (TanStack, Mistral AI, UiPath, OpenSearch…) |
| **TTP-02** PyPI lockfiles | `mistralai==2.4.6` and `guardrails-ai==0.10.1` — both quarantined on PyPI |
| **TTP-03** Payload files | `router_init.js`, `tanstack_runner.js`, `/tmp/transformers.pyz` dropped by the worm |
| **TTP-04** SHA-256 hashes | Exact hash match for known payload binaries — catches renamed copies |
| **TTP-05** Malicious `optionalDependencies` | Injected `github:` URL pointing to the attacker's fork commit (`79ac49ee…`) |
| **TTP-06** IDE/AI persistence | Claude Code `SessionStart` hook and VS Code `folderOpen` task re-executing the payload on every project open |
| **TTP-07** OS persistence | `gh-token-monitor` LaunchAgent (macOS) or systemd service (Linux) surviving reboots |
| **TTP-08** Injected GHA workflows | Fake `CodeQL Analysis` workflow using `toJSON(secrets)` to POST all repository secrets to C2 |
| **TTP-09** C2 domain references | `git-tanstack.com`, `filev2.getsession.org`, `api.masscan.cloud` in any source or config file |
| **TTP-10** Git dead-drop commits | Commits by `claude@users.noreply.github.com` + Dune-named branches mimicking Dependabot |
| **TTP-11** npm ransom token | Token with description `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` in your npm account |

---

## Usage

```bash
# 1. Make executable (one-time)
chmod +x scan-compromised.sh

# 2. Run from your projects root
cd ~/code
./scan-compromised.sh

# 3. Or pass a path directly
./scan-compromised.sh /path/to/projects
```

---

## Reading the output

Each TTP section ends with a status indicator:

| Symbol | Meaning | Action |
|---|---|---|
| ✅ | Clean | Nothing found. No action needed. |
| ⚠️ | Package name matched | Check the exact version in your lockfile against the [compromised versions list](#compromised-versions). The name alone doesn't confirm compromise. |
| 🚨 | High-confidence IOC | Payload file, persistence hook, C2 domain, or ransom token found. Treat the environment as compromised and begin incident response. |

---

## If you find something

### ⛔ Do NOT revoke npm tokens before isolating the machine

The worm creates an npm token with the description `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`. Revoking it while the payload is active **triggers a destructive disk wipe**. Isolate the machine from the network first, then rotate credentials in this order:

1. GitHub tokens (PATs, OAuth, Actions)
2. AWS / cloud credentials
3. SSH private keys
4. npm tokens — **last**, after the machine is isolated

### The worm self-propagates

If any of your CI/CD pipelines installed a compromised package, the worm may have stolen OIDC tokens and used them to publish infected versions of **other packages you maintain** — unrelated to TanStack. Check your npm publish history for unexpected releases after `2026-05-11T19:20Z`.

### Valid SLSA provenance ≠ safe

Compromised packages in this attack carry valid SLSA Build Level 3 provenance attestations generated using stolen OIDC tokens and the legitimate Sigstore stack. Provenance confirms *which pipeline* produced a package — not whether that pipeline was behaving correctly.

---

## Compromised versions

### PyPI

| Package | Compromised | Safe |
|---|---|---|
| `mistralai` | `2.4.6` | `≤ 2.4.5` |
| `guardrails-ai` | `0.10.1` | `≤ 0.10.0` |

### npm — `@tanstack` (42 packages)

<details>
<summary>Show full list</summary>

| Package | Compromised versions |
|---|---|
| `@tanstack/arktype-adapter` | 1.166.12, 1.166.15 |
| `@tanstack/eslint-plugin-router` | 1.161.9, 1.161.12 |
| `@tanstack/eslint-plugin-start` | 0.0.4, 0.0.7 |
| `@tanstack/history` | 1.161.9, 1.161.12 |
| `@tanstack/nitro-v2-vite-plugin` | 1.154.12, 1.154.15 |
| `@tanstack/react-router` | 1.169.5, 1.169.8 |
| `@tanstack/react-router-devtools` | 1.166.16, 1.166.19 |
| `@tanstack/react-router-ssr-query` | 1.166.15, 1.166.18 |
| `@tanstack/react-start` | 1.167.68, 1.167.71 |
| `@tanstack/react-start-client` | 1.166.51, 1.166.54 |
| `@tanstack/react-start-rsc` | 0.0.47, 0.0.50 |
| `@tanstack/react-start-server` | 1.166.55, 1.166.58 |
| `@tanstack/router-cli` | 1.166.46, 1.166.49 |
| `@tanstack/router-core` | 1.169.5, 1.169.8 |
| `@tanstack/router-devtools` | 1.166.16, 1.166.19 |
| `@tanstack/router-devtools-core` | 1.167.6, 1.167.9 |
| `@tanstack/router-generator` | 1.166.45, 1.166.48 |
| `@tanstack/router-plugin` | 1.167.38, 1.167.41 |
| `@tanstack/router-ssr-query-core` | 1.168.3, 1.168.6 |
| `@tanstack/router-utils` | 1.161.11, 1.161.14 |
| `@tanstack/router-vite-plugin` | 1.166.53, 1.166.56 |
| `@tanstack/solid-router` | 1.169.5, 1.169.8 |
| `@tanstack/solid-router-devtools` | 1.166.16, 1.166.19 |
| `@tanstack/solid-router-ssr-query` | 1.166.15, 1.166.18 |
| `@tanstack/solid-start` | 1.167.65, 1.167.68 |
| `@tanstack/solid-start-client` | 1.166.50, 1.166.53 |
| `@tanstack/solid-start-server` | 1.166.54, 1.166.57 |
| `@tanstack/start-client-core` | 1.168.5, 1.168.8 |
| `@tanstack/start-fn-stubs` | 1.161.9, 1.161.12 |
| `@tanstack/start-plugin-core` | 1.169.23, 1.169.26 |
| `@tanstack/start-server-core` | 1.167.33, 1.167.36 |
| `@tanstack/start-static-server-functions` | 1.166.44, 1.166.47 |
| `@tanstack/start-storage-context` | 1.166.38, 1.166.41 |
| `@tanstack/valibot-adapter` | 1.166.12, 1.166.15 |
| `@tanstack/virtual-file-routes` | 1.161.10, 1.161.13 |
| `@tanstack/vue-router` | 1.169.5, 1.169.8 |
| `@tanstack/vue-router-devtools` | 1.166.16, 1.166.19 |
| `@tanstack/vue-router-ssr-query` | 1.166.15, 1.166.18 |
| `@tanstack/vue-start` | 1.167.61, 1.167.64 |
| `@tanstack/vue-start-client` | 1.166.46, 1.166.49 |
| `@tanstack/vue-start-server` | 1.166.50, 1.166.53 |
| `@tanstack/zod-adapter` | 1.166.12, 1.166.15 |

</details>

### npm — `@mistralai` (3 packages)

| Package | Compromised versions |
|---|---|
| `@mistralai/mistralai` | 2.2.2, 2.2.3, 2.2.4 |
| `@mistralai/mistralai-azure` | 1.7.1, 1.7.2, 1.7.3 |
| `@mistralai/mistralai-gcp` | 1.7.1, 1.7.2, 1.7.3 |

### npm — `@opensearch-project` (1 package)

| Package | Compromised versions |
|---|---|
| `@opensearch-project/opensearch` | 3.5.3, 3.6.2, 3.7.0, 3.8.0 |

### npm — `@uipath` (65 packages), `@squawk` (22), `@tallyui` (10), and others

<details>
<summary>Show full list</summary>

| Package | Compromised version(s) |
|---|---|
| `@uipath/access-policy-sdk` | 0.3.1 |
| `@uipath/access-policy-tool` | 0.3.1 |
| `@uipath/admin-tool` | 0.1.1 |
| `@uipath/agent-sdk` | 1.0.2 |
| `@uipath/agent-tool` | 1.0.1 |
| `@uipath/agent.sdk` | 0.0.18 |
| `@uipath/aops-policy-tool` | 0.3.1 |
| `@uipath/ap-chat` | 1.5.7 |
| `@uipath/api-workflow-tool` | 1.0.1 |
| `@uipath/apollo-core` | 5.9.2 |
| `@uipath/apollo-react` | 4.24.5 |
| `@uipath/apollo-wind` | 2.16.2 |
| `@uipath/auth` | 1.0.1 |
| `@uipath/case-tool` | 1.0.1 |
| `@uipath/cli` | 1.0.1 |
| `@uipath/codedagent-tool` | 1.0.1 |
| `@uipath/codedagents-tool` | 0.1.12 |
| `@uipath/codedapp-tool` | 1.0.1 |
| `@uipath/common` | 1.0.1 |
| `@uipath/context-grounding-tool` | 0.1.1 |
| `@uipath/data-fabric-tool` | 1.0.2 |
| `@uipath/docsai-tool` | 1.0.1 |
| `@uipath/filesystem` | 1.0.1 |
| `@uipath/flow-tool` | 1.0.2 |
| `@uipath/functions-tool` | 1.0.1 |
| `@uipath/gov-tool` | 0.3.1 |
| `@uipath/identity-tool` | 0.1.1 |
| `@uipath/insights-sdk` | 1.0.1 |
| `@uipath/insights-tool` | 1.0.1 |
| `@uipath/integrationservice-sdk` | 1.0.2 |
| `@uipath/integrationservice-tool` | 1.0.2 |
| `@uipath/llmgw-tool` | 1.0.1 |
| `@uipath/maestro-sdk` | 1.0.1 |
| `@uipath/maestro-tool` | 1.0.1 |
| `@uipath/orchestrator-tool` | 1.0.1 |
| `@uipath/packager-tool-apiworkflow` | 0.0.19 |
| `@uipath/packager-tool-bpmn` | 0.0.9 |
| `@uipath/packager-tool-case` | 0.0.9 |
| `@uipath/packager-tool-connector` | 0.0.19 |
| `@uipath/packager-tool-flow` | 0.0.19 |
| `@uipath/packager-tool-functions` | 0.1.1 |
| `@uipath/packager-tool-webapp` | 1.0.6 |
| `@uipath/packager-tool-workflowcompiler` | 0.0.16 |
| `@uipath/packager-tool-workflowcompiler-browser` | 0.0.34 |
| `@uipath/platform-tool` | 1.0.1 |
| `@uipath/project-packager` | 1.1.16 |
| `@uipath/resource-tool` | 1.0.1 |
| `@uipath/resourcecatalog-tool` | 0.1.1 |
| `@uipath/resources-tool` | 0.1.11 |
| `@uipath/robot` | 1.3.4 |
| `@uipath/rpa-legacy-tool` | 1.0.1 |
| `@uipath/rpa-tool` | 0.9.5 |
| `@uipath/solution-packager` | 0.0.35 |
| `@uipath/solution-tool` | 1.0.1 |
| `@uipath/solutionpackager-sdk` | 1.0.11 |
| `@uipath/solutionpackager-tool-core` | 0.0.34 |
| `@uipath/tasks-tool` | 1.0.1 |
| `@uipath/telemetry` | 0.0.7 |
| `@uipath/test-manager-tool` | 1.0.2 |
| `@uipath/tool-workflowcompiler` | 0.0.12 |
| `@uipath/traces-tool` | 1.0.1 |
| `@uipath/ui-widgets-multi-file-upload` | 1.0.1 |
| `@uipath/uipath-python-bridge` | 1.0.1 |
| `@uipath/vertical-solutions-tool` | 1.0.1 |
| `@uipath/vss` | 0.1.6 |
| `@uipath/widget.sdk` | 1.2.3 |
| `@squawk/airport-data` | 0.7.4–0.7.8 |
| `@squawk/airports` | 0.6.2–0.6.6 |
| `@squawk/airspace` | 0.8.1–0.8.5 |
| `@squawk/airspace-data` | 0.5.3–0.5.7 |
| `@squawk/airway-data` | 0.5.4–0.5.8 |
| `@squawk/airways` | 0.4.2–0.4.6 |
| `@squawk/fix-data` | 0.6.4–0.6.8 |
| `@squawk/fixes` | 0.3.2–0.3.6 |
| `@squawk/flight-math` | 0.5.4–0.5.8 |
| `@squawk/flightplan` | 0.5.2–0.5.6 |
| `@squawk/geo` | 0.4.4–0.4.8 |
| `@squawk/icao-registry` | 0.5.2–0.5.6 |
| `@squawk/icao-registry-data` | 0.8.4–0.8.8 |
| `@squawk/mcp` | 0.9.1–0.9.5 |
| `@squawk/navaid-data` | 0.6.4–0.6.8 |
| `@squawk/navaids` | 0.4.2–0.4.6 |
| `@squawk/notams` | 0.3.6–0.3.10 |
| `@squawk/procedure-data` | 0.7.3–0.7.7 |
| `@squawk/procedures` | 0.5.2–0.5.6 |
| `@squawk/types` | 0.8.1–0.8.5 |
| `@squawk/units` | 0.4.3–0.4.7 |
| `@squawk/weather` | 0.5.6–0.5.10 |
| `@tallyui/components` | 1.0.1–1.0.3 |
| `@tallyui/connector-medusa` | 1.0.1–1.0.3 |
| `@tallyui/connector-shopify` | 1.0.1–1.0.3 |
| `@tallyui/connector-vendure` | 1.0.1–1.0.3 |
| `@tallyui/connector-woocommerce` | 1.0.1–1.0.3 |
| `@tallyui/core` | 0.2.1–0.2.3 |
| `@tallyui/database` | 1.0.1–1.0.3 |
| `@tallyui/pos` | 0.1.1–0.1.3 |
| `@tallyui/storage-sqlite` | 0.2.1–0.2.3 |
| `@tallyui/theme` | 0.2.1–0.2.3 |
| `@beproduct/nestjs-auth` | 0.1.2–0.1.19 |
| `@draftauth/client` | 0.2.1, 0.2.2 |
| `@draftauth/core` | 0.13.1, 0.13.2 |
| `@draftlab/auth` | 0.24.1, 0.24.2 |
| `@draftlab/auth-router` | 0.5.1, 0.5.2 |
| `@draftlab/db` | 0.16.1, 0.16.2 |
| `@dirigible-ai/sdk` | 0.6.2, 0.6.3 |
| `@mesadev/rest` | 0.28.3 |
| `@mesadev/saguaro` | 0.4.22 |
| `@mesadev/sdk` | 0.28.3 |
| `@ml-toolkit-ts/preprocessing` | 1.0.2, 1.0.3 |
| `@ml-toolkit-ts/xgboost` | 1.0.3, 1.0.4 |
| `@supersurkhet/cli` | 0.0.2–0.0.7 |
| `@supersurkhet/sdk` | 0.0.2–0.0.7 |
| `@taskflow-corp/cli` | 0.1.24–0.1.29 |
| `@tolka/cli` | 1.0.2–1.0.6 |
| `agentwork-cli` | 0.1.4, 0.1.5 |
| `cmux-agent-mcp` | 0.1.3–0.1.8 |
| `cross-stitch` | 1.1.3–1.1.7 |
| `git-branch-selector` | 1.3.3–1.3.7 |
| `git-git-git` | 1.0.8–1.0.12 |
| `ml-toolkit-ts` | 1.0.4, 1.0.5 |
| `nextmove-mcp` | 0.1.3–0.1.7 |
| `safe-action` | 0.8.3, 0.8.4 |
| `ts-dna` | 3.0.1–3.0.5 |
| `wot-api` | 0.8.1–0.8.4 |

</details>

---

## IOCs at a glance

```
# Malicious payload hashes (SHA-256)
router_init.js      ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
tanstack_runner.js  2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96

# C2 / attacker infrastructure
git-tanstack.com
filev2.getsession.org
api.masscan.cloud
seed1.getsession.org

# Malicious GitHub commit (attacker's fork)
tanstack/router@79ac49eedf774dd4b0cfa308722bc463cfe5885c

# Dead-drop commit identity
author:  lazarov@lazarov.tech
```

---

## Sources

- [SafeDep — Full package list & technical analysis](https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/)
- [StepSecurity — Attack deep-dive & IOCs](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [TanStack — Official postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [Snyk — TanStack packages compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Wiz — Mini Shai-Hulud strikes again](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
