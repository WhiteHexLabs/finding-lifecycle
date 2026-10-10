#!/usr/bin/env bash
# setup_and_run.sh — self-contained PoC runner template.
#
# Rules enforced by the lifecycle:
#   - pinned toolchain only; this script never downloads anything
#   - no `curl | sh`, no floating branches
#   - external prerequisites (toolchain, RPC) must be declared, not installed
#   - the script must terminate with a single result marker:
#       "RESULT: PASS"    exploit reproduced, assertions held
#       "RESULT: REFUTED" the claimed attack is blocked (refutation package)
#
# Place this file at the root of the PoC package next to manifest.yaml.

set -euo pipefail

# --- pinned toolchain -------------------------------------------------------
FORGE_PINNED_VERSION="0.2.2"   # must match manifest.yaml dependencies.pinned

if ! command -v forge >/dev/null 2>&1; then
  echo "setup_and_run.sh: forge not found (pinned: ${FORGE_PINNED_VERSION})" >&2
  exit 2
fi
FORGE_VERSION="$(forge --version | awk '{print $NF}')"
FORGE_VERSION="${FORGE_VERSION#v}"
if [ "${FORGE_VERSION}" != "${FORGE_PINNED_VERSION}" ]; then
  echo "setup_and_run.sh: forge ${FORGE_VERSION} != pinned ${FORGE_PINNED_VERSION}" >&2
  exit 2
fi

# --- declared external prerequisites ----------------------------------------
# An archive RPC endpoint for the pinned block. Never embed a key here.
: "${MAINNET_RPC_URL:?MAINNET_RPC_URL must point at an archive RPC for the pinned block}"

# --- run --------------------------------------------------------------------
LOG=run.log
forge test --match-path 'test/Exploit.t.sol' --fork-url "$MAINNET_RPC_URL" -vvv | tee "$LOG"

# The clean-run gate greps the log for the expected assertion identifiers
# listed in manifest.yaml, so name your tests after them.
grep -q "suite result: ok" "$LOG"

echo "RESULT: PASS"
