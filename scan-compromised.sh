#!/usr/bin/env bash
# ============================================================
#  Mini Shai-Hulud Supply Chain Scanner — TeamPCP Full TTP
#  Covers the May 11 2026 attack and all known TeamPCP TTPs:
#    - Compromised package versions (npm + PyPI)
#    - Malicious payload files & hashes
#    - IDE/AI agent persistence hooks (Claude Code, VS Code)
#    - OS-level persistence (macOS LaunchAgent, Linux systemd)
#    - Injected GitHub Actions workflows
#    - Dead-drop git commit signatures
#    - Suspicious Dune-named branches
#    - npm token ransom marker
#    - C2 domain references in source/config files
#    - Malicious optionalDependencies in node_modules
# ============================================================

FOUND=0
SCAN_DIR="${1:-.}"   # pass a path as arg or defaults to current dir

# ---- Colours -----------------------------------------------
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

flag()  { FOUND=1; echo -e "${RED}🚨 $*${RST}"; }
warn()  { FOUND=1; echo -e "${YEL}⚠️  $*${RST}"; }
ok()    { echo -e "${GRN}✅ $*${RST}"; }
hdr()   { echo -e "\n${CYN}${BLD}--- $* ---${RST}"; }

# ---- IOC lists ---------------------------------------------

PACKAGES="@tanstack/arktype-adapter|@tanstack/eslint-plugin-router|@tanstack/eslint-plugin-start|@tanstack/history|@tanstack/nitro-v2-vite-plugin|@tanstack/react-router|@tanstack/react-router-devtools|@tanstack/react-router-ssr-query|@tanstack/react-start|@tanstack/react-start-client|@tanstack/react-start-rsc|@tanstack/react-start-server|@tanstack/router-cli|@tanstack/router-core|@tanstack/router-devtools|@tanstack/router-devtools-core|@tanstack/router-generator|@tanstack/router-plugin|@tanstack/router-ssr-query-core|@tanstack/router-utils|@tanstack/router-vite-plugin|@tanstack/solid-router|@tanstack/solid-router-devtools|@tanstack/solid-router-ssr-query|@tanstack/solid-start|@tanstack/solid-start-client|@tanstack/solid-start-server|@tanstack/start-client-core|@tanstack/start-fn-stubs|@tanstack/start-plugin-core|@tanstack/start-server-core|@tanstack/start-static-server-functions|@tanstack/start-storage-context|@tanstack/valibot-adapter|@tanstack/virtual-file-routes|@tanstack/vue-router|@tanstack/vue-router-devtools|@tanstack/vue-router-ssr-query|@tanstack/vue-start|@tanstack/vue-start-client|@tanstack/vue-start-server|@tanstack/zod-adapter|@mistralai/mistralai|@mistralai/mistralai-azure|@mistralai/mistralai-gcp|@uipath/access-policy-sdk|@uipath/access-policy-tool|@uipath/admin-tool|@uipath/agent-sdk|@uipath/agent-tool|@uipath/agent.sdk|@uipath/aops-policy-tool|@uipath/ap-chat|@uipath/api-workflow-tool|@uipath/apollo-core|@uipath/apollo-react|@uipath/apollo-wind|@uipath/auth|@uipath/case-tool|@uipath/cli|@uipath/codedagent-tool|@uipath/codedagents-tool|@uipath/codedapp-tool|@uipath/common|@uipath/context-grounding-tool|@uipath/data-fabric-tool|@uipath/docsai-tool|@uipath/filesystem|@uipath/flow-tool|@uipath/functions-tool|@uipath/gov-tool|@uipath/identity-tool|@uipath/insights-sdk|@uipath/insights-tool|@uipath/integrationservice-sdk|@uipath/integrationservice-tool|@uipath/llmgw-tool|@uipath/maestro-sdk|@uipath/maestro-tool|@uipath/orchestrator-tool|@uipath/packager-tool-apiworkflow|@uipath/packager-tool-bpmn|@uipath/packager-tool-case|@uipath/packager-tool-connector|@uipath/packager-tool-flow|@uipath/packager-tool-functions|@uipath/packager-tool-webapp|@uipath/packager-tool-workflowcompiler|@uipath/packager-tool-workflowcompiler-browser|@uipath/platform-tool|@uipath/project-packager|@uipath/resource-tool|@uipath/resourcecatalog-tool|@uipath/resources-tool|@uipath/robot|@uipath/rpa-legacy-tool|@uipath/rpa-tool|@uipath/solution-packager|@uipath/solution-tool|@uipath/solutionpackager-sdk|@uipath/solutionpackager-tool-core|@uipath/tasks-tool|@uipath/telemetry|@uipath/test-manager-tool|@uipath/tool-workflowcompiler|@uipath/traces-tool|@uipath/ui-widgets-multi-file-upload|@uipath/uipath-python-bridge|@uipath/vertical-solutions-tool|@uipath/vss|@uipath/widget.sdk|@opensearch-project/opensearch|@squawk/airport-data|@squawk/airports|@squawk/airspace|@squawk/airspace-data|@squawk/airway-data|@squawk/airways|@squawk/fix-data|@squawk/fixes|@squawk/flight-math|@squawk/flightplan|@squawk/geo|@squawk/icao-registry|@squawk/icao-registry-data|@squawk/mcp|@squawk/navaid-data|@squawk/navaids|@squawk/notams|@squawk/procedure-data|@squawk/procedures|@squawk/types|@squawk/units|@squawk/weather|@tallyui/components|@tallyui/connector-medusa|@tallyui/connector-shopify|@tallyui/connector-vendure|@tallyui/connector-woocommerce|@tallyui/core|@tallyui/database|@tallyui/pos|@tallyui/storage-sqlite|@tallyui/theme|@beproduct/nestjs-auth|@draftauth/client|@draftauth/core|@draftlab/auth|@draftlab/auth-router|@draftlab/db|@dirigible-ai/sdk|@mesadev/rest|@mesadev/saguaro|@mesadev/sdk|@ml-toolkit-ts/preprocessing|@ml-toolkit-ts/xgboost|@supersurkhet/cli|@supersurkhet/sdk|@taskflow-corp/cli|@tolka/cli|agentwork-cli|cmux-agent-mcp|cross-stitch|git-branch-selector|git-git-git|ml-toolkit-ts|nextmove-mcp|safe-action|ts-dna|wot-api"

# Known malicious file SHA-256 hashes
HASH_router_init="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
HASH_tanstack_runner="2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"

# C2 / attacker-controlled domains
C2_DOMAINS="git-tanstack\.com|filev2\.getsession\.org|api\.masscan\.cloud|seed1\.getsession\.org|seed2\.getsession\.org|seed3\.getsession\.org"

# Dune-universe branch name keywords used for dead-drop commits
DUNE_WORDS="atreides|cogitor|fedaykin|fremen|futar|gesserit|ghola|harkonnen|heighliner|kanly|kralizec|lasgun|lza|melange|mentat|navigator|ornithopter|phibian|powindah|prana|prescient|sandworm|sardaukar|sayyadina|sietch|siridar|slig|stillsuit|thumper|tleilaxu"

# Malicious commit author used for GitHub dead-drop exfiltration
DEADDROP_AUTHOR="claude@users.noreply.github.com"

# ============================================================

echo ""
echo -e "${BLD}======================================================${RST}"
echo -e "${BLD} Mini Shai-Hulud Supply Chain Scanner — TeamPCP TTPs${RST}"
echo -e "${BLD} Scanning: $(realpath "$SCAN_DIR")${RST}"
echo -e "${BLD} $(date)${RST}"
echo -e "${BLD}======================================================${RST}"

# ============================================================
# 1. COMPROMISED npm LOCKFILES
# ============================================================
hdr "T1195.001 · Supply Chain Compromise: Software Dependencies — npm lockfiles"
NPM_CLEAN=1
while IFS= read -r lockfile; do
  MATCHES=$(grep -oE "$PACKAGES" "$lockfile" | sort -u)
  if [ -n "$MATCHES" ]; then
    warn "MATCH in: $lockfile"
    echo "$MATCHES" | while read -r m; do echo "          → $m"; done
    NPM_CLEAN=0
  fi
done < <(find "$SCAN_DIR" -not -path "*/node_modules/*" -not -path "*/.git/*" \
  \( -name "package-lock.json" -o -name "pnpm-lock.yaml" -o -name "yarn.lock" \))
[ "$NPM_CLEAN" -eq 1 ] && ok "No compromised npm packages found in lockfiles"

# ============================================================
# 2. COMPROMISED PyPI PACKAGES
# ============================================================
hdr "T1195.001 · Supply Chain Compromise: Software Dependencies — PyPI lockfiles"
PY_CLEAN=1
while IFS= read -r reqfile; do
  if grep -qiE "mistralai==2\.4\.6|guardrails.ai==0\.10\.1" "$reqfile" 2>/dev/null; then
    warn "MATCH in: $reqfile"
    grep -iE "mistralai==2\.4\.6|guardrails.ai==0\.10\.1" "$reqfile" | \
      while read -r m; do echo "          → $m"; done
    PY_CLEAN=0
  fi
done < <(find "$SCAN_DIR" -not -path "*/.git/*" \
  \( -name "requirements*.txt" -o -name "Pipfile.lock" -o -name "poetry.lock" \))
[ "$PY_CLEAN" -eq 1 ] && ok "No compromised PyPI packages found"

# ============================================================
# 3. MALICIOUS PAYLOAD FILES (by name)
# ============================================================
hdr "T1105 · Ingress Tool Transfer — malicious payload files"
for fname in "router_init.js" "tanstack_runner.js"; do
  while IFS= read -r f; do
    flag "MALICIOUS FILE: $f"
  done < <(find "$SCAN_DIR" -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -name "$fname" 2>/dev/null)
done
# PyPI dropper
if [ -f /tmp/transformers.pyz ]; then
  flag "PAYLOAD FILE: /tmp/transformers.pyz — PyPI dropper present, environment is compromised!"
else
  ok "/tmp/transformers.pyz not present"
fi

# ============================================================
# 4. HASH VERIFICATION of suspicious JS files
# ============================================================
hdr "T1027 · Obfuscated Files or Information — SHA-256 payload hash check"
HASH_CMD=""
if command -v sha256sum &>/dev/null; then HASH_CMD="sha256sum"
elif command -v shasum &>/dev/null;   then HASH_CMD="shasum -a 256"
fi
if [ -n "$HASH_CMD" ]; then
  while IFS= read -r jsfile; do
    HASH=$(${HASH_CMD} "$jsfile" 2>/dev/null | awk '{print $1}')
    if [ "$HASH" = "$HASH_router_init" ]; then
      flag "HASH MATCH router_init.js payload: $jsfile ($HASH)"
    elif [ "$HASH" = "$HASH_tanstack_runner" ]; then
      flag "HASH MATCH tanstack_runner.js payload: $jsfile ($HASH)"
    fi
  done < <(find "$SCAN_DIR" -not -path "*/.git/*" -name "*.js" -size +1M 2>/dev/null)
  ok "Hash check complete"
else
  echo "  (skipped — sha256sum/shasum not available)"
fi

# ============================================================
# 5. MALICIOUS optionalDependencies in node_modules
# ============================================================
hdr "T1195.001 · Supply Chain Compromise: Software Dependencies — malicious optionalDependencies"
while IFS= read -r pkgjson; do
  if grep -q "79ac49eedf774dd4b0cfa308722bc463cfe5885c\|github:tanstack/router#" "$pkgjson" 2>/dev/null; then
    flag "MALICIOUS optionalDependency in: $pkgjson"
  fi
done < <(find "$SCAN_DIR" -path "*/node_modules/*/package.json" 2>/dev/null)
ok "optionalDependencies check done"

# ============================================================
# 6. IDE / AI AGENT PERSISTENCE (Claude Code + VS Code)
# ============================================================
hdr "T1546 · Event Triggered Execution — IDE & AI agent persistence hooks"
# Scan project dirs
while IFS= read -r f; do
  if grep -qE "router_runtime|setup\.mjs|SessionStart|folderOpen" "$f" 2>/dev/null; then
    flag "PERSISTENCE HOOK in: $f"
    grep -E "router_runtime|setup\.mjs|SessionStart|folderOpen" "$f" | \
      while read -r line; do echo "          → $line"; done
  fi
done < <(find "$SCAN_DIR" -not -path "*/node_modules/*" -not -path "*/.git/*" \
  \( \( -name "settings.json" -path "*/.claude/*" \) \
   -o \( -name "tasks.json"   -path "*/.vscode/*" \) \) 2>/dev/null)
# Also check home directory
for homefile in \
  "$HOME/.claude/settings.json" \
  "$HOME/.vscode/tasks.json"; do
  if [ -f "$homefile" ]; then
    if grep -qE "router_runtime|setup\.mjs|SessionStart|folderOpen|tanstack" "$homefile" 2>/dev/null; then
      flag "PERSISTENCE HOOK in home dir: $homefile"
      grep -E "router_runtime|setup\.mjs|SessionStart|folderOpen|tanstack" "$homefile" | \
        while read -r line; do echo "          → $line"; done
    fi
  fi
done
# These files should not exist at all — flag unconditionally if present
for homefile in \
  "$HOME/.claude/setup.mjs" \
  "$HOME/.vscode/setup.mjs" \
  "$HOME/.claude/router_runtime.js"; do
  if [ -f "$homefile" ]; then
    flag "UNEXPECTED PAYLOAD FILE in home dir: $homefile"
  fi
done
ok "IDE persistence check done"

# ============================================================
# 7. OS-LEVEL PERSISTENCE (macOS LaunchAgent / Linux systemd)
# ============================================================
hdr "T1543.001/002 · Create or Modify System Process — LaunchAgent (macOS) / Systemd Service (Linux)"
# macOS
PLIST="$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
if [ -f "$PLIST" ]; then
  flag "macOS LaunchAgent found: $PLIST"
fi
# Linux systemd
SERVICE="$HOME/.config/systemd/user/gh-token-monitor.service"
if [ -f "$SERVICE" ]; then
  flag "Linux systemd service found: $SERVICE"
fi
# Monitor script + data dir
[ -f "$HOME/.local/bin/gh-token-monitor.sh" ] && flag "Monitor script: $HOME/.local/bin/gh-token-monitor.sh"
[ -d "$HOME/.config/gh-token-monitor" ]        && flag "Monitor data dir: $HOME/.config/gh-token-monitor"
[ "$FOUND" -eq 0 ] && ok "No OS-level persistence artifacts found"

# ============================================================
# 8. INJECTED GITHUB ACTIONS WORKFLOWS (CI/CD Pipeline Poisoning)
# ============================================================
hdr "T1072 · Software Deployment Tools — injected CI/CD workflows"
GHA_CLEAN=1
while IFS= read -r wf; do
  # Check for the two known patterns: toJSON(secrets) exfil and C2 POST
  if grep -qE "toJSON\(secrets\)|masscan\.cloud|git-tanstack\.com|filev2\.getsession" "$wf" 2>/dev/null; then
    flag "MALICIOUS WORKFLOW: $wf"
    grep -E "toJSON\(secrets\)|masscan\.cloud|git-tanstack\.com|filev2\.getsession" "$wf" | \
      while read -r line; do echo "          → $line"; done
    GHA_CLEAN=0
  fi
done < <(find "$SCAN_DIR" -not -path "*/.git/*" -path "*/.github/workflows/*.yml" 2>/dev/null
         find "$SCAN_DIR" -not -path "*/.git/*" -path "*/.github/workflows/*.yaml" 2>/dev/null)
[ "$GHA_CLEAN" -eq 1 ] && ok "No injected GitHub Actions workflows found"

# ============================================================
# 9. C2 DOMAIN REFERENCES IN SOURCE / CONFIG FILES
# ============================================================
hdr "T1071.001 · Application Layer Protocol: Web Protocols — C2 domain references"
C2_CLEAN=1
while IFS= read -r f; do
  HITS=$(grep -oE "$C2_DOMAINS" "$f" 2>/dev/null | sort -u)
  if [ -n "$HITS" ]; then
    flag "C2 DOMAIN in: $f"
    echo "$HITS" | while read -r h; do echo "          → $h"; done
    C2_CLEAN=0
  fi
done < <(find "$SCAN_DIR" \
  -not -path "*/node_modules/*" \
  -not -path "*/.git/*" \
  -not -path "*/dist/*" \
  \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.json" \
   -o -name "*.yml" -o -name "*.yaml" -o -name "*.sh" -o -name "*.py" \) \
  2>/dev/null)
[ "$C2_CLEAN" -eq 1 ] && ok "No C2 domain references found"

# ============================================================
# 10. GIT HISTORY — DEAD-DROP COMMIT SIGNATURES
# ============================================================
hdr "T1102.001 · Web Service: Dead Drop Resolver — git history dead-drop commits"
while IFS= read -r gitdir; do
  REPO=$(dirname "$gitdir")
  # Check for commits authored by the spoofed Claude bot account
  DEADDROP_COMMITS=$(git -C "$REPO" log --all --format="%H %ae %s" 2>/dev/null | \
    grep "$DEADDROP_AUTHOR")
  if [ -n "$DEADDROP_COMMITS" ]; then
    flag "DEAD-DROP COMMITS in $REPO (author: $DEADDROP_AUTHOR):"
    echo "$DEADDROP_COMMITS" | while read -r line; do echo "          → $line"; done
  fi
  # Check for Dune-named dependabot-style branches used as dead-drops
  DUNE_BRANCHES=$(git -C "$REPO" branch -a 2>/dev/null | \
    grep -E "dependabot/github_actions/format/($DUNE_WORDS)")
  if [ -n "$DUNE_BRANCHES" ]; then
    flag "DUNE DEAD-DROP BRANCHES in $REPO:"
    echo "$DUNE_BRANCHES" | while read -r b; do echo "          → $b"; done
  fi
done < <(find "$SCAN_DIR" -maxdepth 3 -name ".git" -type d 2>/dev/null)
ok "Git history check done"

# ============================================================
# 11. npm TOKEN RANSOM MARKER
# ============================================================
hdr "T1485 · Data Destruction — npm ransom token (disk wipe trigger)"
if command -v npm &>/dev/null; then
  RANSOM_TOKEN=$(npm token list 2>/dev/null | grep -i "IfYouRevokeThisToken")
  if [ -n "$RANSOM_TOKEN" ]; then
    flag "RANSOM TOKEN FOUND in npm token list!"
    echo -e "  ${RED}⛔ DO NOT REVOKE before isolating this machine — revocation triggers a disk wipe.${RST}"
    echo "  Run: npm token list"
  else
    ok "No ransom token found in npm token list"
  fi
else
  echo "  (skipped — npm not found in PATH)"
fi

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo -e "${BLD}======================================================${RST}"
if [ "$FOUND" -eq 0 ]; then
  echo -e "${GRN}${BLD} ✅  All checks passed. No TeamPCP IOCs detected.${RST}"
else
  echo -e "${RED}${BLD} ⚠️   IOCs found — review matches above immediately.${RST}"
  echo ""
  echo -e "${YEL}  Reminder: If compromised, DO NOT revoke npm tokens${RST}"
  echo -e "${YEL}  before isolating the machine. Revocation triggers${RST}"
  echo -e "${YEL}  a destructive disk wipe by the payload.${RST}"
fi
echo -e "${BLD}======================================================${RST}"
echo ""
