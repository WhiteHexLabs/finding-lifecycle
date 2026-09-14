#!/usr/bin/env python3
"""Controlled local-chain exercise for the finding-lifecycle workflow.

Implements plan.md section 5: "另用受控测试合约在本地链上构造成功与反证样例,
验证完整流程". This validates the WORKFLOW only; it does not replace mainnet
fork forensics on a real target.

What it does, end to end:

 1. start anvil (local chain) and deploy two controlled targets:
    VulnerableVault (reentrancy-vulnerable, seeded with 10 ETH victim funds)
    and GuardedVault (hardened variant, same seed);
 2. pin the block (number + hash) right after deployment;
 3. run the real PoCs against a pinned fork of that local chain:
    - success case: attacker drains VulnerableVault ("ProfitWithdrawn");
    - refutation case: the same attack extracts nothing from GuardedVault
      with a stated blocking mechanism ("RESULT: REFUTED");
 4. drive the lifecycle CLI through the full pipeline with those artifacts:
    finding A (success) reaches SUBMITTED via all eight gates including a
    clean-directory package run; finding B (false positive) closes REFUTED
    with fork counter-evidence and a conclusion boundary.

Usage: python3 demo/drive.py [--case-root DIR] [--rpc-port N]
Requires: forge, anvil, cast on PATH (Foundry).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import date
from pathlib import Path

import yaml

DEMO = Path(__file__).resolve().parent
REPO = DEMO.parent
LC = [sys.executable, str(REPO / "scripts" / "lifecycle.py")]
FORGE_STD_REF = "foundry-rs/forge-std@v1.9.7"
SEED_ETH = 10
STAKE_ETH = 1


def say(msg: str) -> None:
    print(f"\n=== {msg}")


def run(cmd, *, cwd=None, env=None, check=True, stdout=None, capture=True):
    shown = " ".join(str(c) for c in cmd[:6])
    print(f"+ {shown}{' ...' if len(cmd) > 6 else ''}")
    return subprocess.run(
        [str(c) for c in cmd], cwd=cwd, env=env, check=check, text=True,
        stdout=stdout if stdout is not None else (subprocess.PIPE if capture else None),
        stderr=subprocess.STDOUT if stdout is not None else None,
    )


def lc(root: Path, *args, expect_ok=True):
    cmd = LC + [str(a) for a in args] + ["--case-root", str(root)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    print(f"$ lifecycle.py {' '.join(str(a) for a in args[:3])} ...")
    if out:
        for line in out.splitlines():
            print(f"    {line}")
    if expect_ok and r.returncode != 0:
        raise SystemExit(f"lifecycle command failed ({r.returncode}): {' '.join(cmd)}")
    return r


def sha(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def wyaml(path, obj) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=True)
    return str(path)


def wfile(path, content) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def revision(root: Path, fid: str) -> int:
    text = (root / "findings" / f"{fid}.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    end = lines.index("---", 1)
    fm = yaml.safe_load("\n".join(lines[1:end]))
    return fm["revision"]


def advance(root: Path, fid: str, reviewer: str, reason: str):
    lc(root, "advance", "--id", fid, "--reviewer", reviewer, "--reason", reason,
       "--expected-revision", revision(root, fid))


def register(root: Path, title: str, claim: str, orig_id: str) -> str:
    src = wyaml(Path(tempfile.mkdtemp(prefix="fl-src-")) / "finding-source.yaml", {
        "title": title,
        "claim": claim,
        "sources": {"auditor": "demo-scan", "original_finding_id": orig_id,
                    "audit_round": "demo-round-1"},
        "prescreen": [
            {"aspect": "scope", "status": "PASS", "evidence": "program.yaml scope",
             "explanation": "target deployment is in scope"},
            {"aspect": "authority", "status": "PASS", "evidence": "no role needed",
             "explanation": "attack needs no privileged role"},
            {"aspect": "exclusion", "status": "PASS", "evidence": "rules E1",
             "explanation": "not privileged, not mev"},
            {"aspect": "duplication", "status": "PASS", "evidence": "index empty",
             "explanation": "no prior finding matches"},
        ],
    })
    r = lc(root, "register", "--from", src, "--json")
    return json.loads(r.stdout)["id"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-root", default=str(DEMO / "run" / "case"))
    ap.add_argument("--rpc-port", type=int, default=8545)
    args = ap.parse_args()

    for tool in ("forge", "anvil", "cast"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} not found on PATH; install Foundry first")
    forge_version = subprocess.run(["forge", "--version"], capture_output=True,
                                   text=True).stdout.split()[-1]

    case_root = Path(args.case_root).resolve()
    if case_root.exists():
        raise SystemExit(f"case root already exists: {case_root} (remove it or pass another --case-root)")
    rpc = f"http://127.0.0.1:{args.rpc_port}"

    if not (DEMO / "lib" / "forge-std").is_dir():
        say(f"installing pinned forge-std ({FORGE_STD_REF})")
        run(["forge", "install", FORGE_STD_REF, "--no-git"], cwd=DEMO)

    say("building the controlled contracts")
    run(["forge", "build"], cwd=DEMO)

    say(f"starting anvil on {rpc}")
    (DEMO / "run").mkdir(parents=True, exist_ok=True)
    anvil_log = open(DEMO / "run" / "anvil.log", "w")
    anvil = subprocess.Popen(["anvil", "--port", str(args.rpc_port)],
                             stdout=anvil_log, stderr=anvil_log)
    try:
        for _ in range(60):
            r = subprocess.run(["cast", "block-number", "--rpc-url", rpc],
                               capture_output=True, text=True)
            if r.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise SystemExit("anvil did not come up")
        # take the funded account keys from this very anvil instance instead
        # of hardcoding them (the anvil default test accounts, public by design)
        import re as _re
        boot = (DEMO / "run" / "anvil.log").read_text(encoding="utf-8", errors="ignore")
        keys = _re.findall(r"\((\d+)\) (0x[0-9a-fA-F]{64})", boot)
        accounts = {i: k for i, k in keys}
        ANVIL_KEY0 = accounts["0"]  # deployer
        VICTIM_KEY = accounts["1"]  # victim depositor

        say("deploying VulnerableVault + GuardedVault, then a victim deposits 10 ETH into each")
        def deploy(name: str, value_eth: int) -> str:
            bytecode = subprocess.run(["forge", "inspect", name, "bytecode"],
                                      cwd=DEMO, capture_output=True, text=True,
                                      check=True).stdout.strip()
            r = subprocess.run(
                ["cast", "send", "--rpc-url", rpc, "--private-key", ANVIL_KEY0,
                 "--json", "--create", bytecode],
                capture_output=True, text=True, check=True)
            addr = json.loads(r.stdout)["contractAddress"]
            subprocess.run(
                ["cast", "send", "--rpc-url", rpc, "--private-key", VICTIM_KEY,
                 "--json", addr, "deposit()", "--value", f"{value_eth}ether"],
                capture_output=True, text=True, check=True)
            return addr
        vault = deploy("VulnerableVault", SEED_ETH)
        guarded = deploy("GuardedVault", SEED_ETH)

        pin = int(subprocess.run(["cast", "block-number", "--rpc-url", rpc],
                                 capture_output=True, text=True).stdout.strip())
        block_info = json.loads(subprocess.run(
            ["cast", "block", str(pin), "--json", "--rpc-url", rpc],
            capture_output=True, text=True, check=True).stdout)
        block_hash = block_info["hash"]
        code_vault = subprocess.run(["cast", "code", vault, "--rpc-url", rpc],
                                    capture_output=True, text=True).stdout.strip()
        code_guarded = subprocess.run(["cast", "code", guarded, "--rpc-url", rpc],
                                      capture_output=True, text=True).stdout.strip()
        say(f"deployed vault={vault} guarded={guarded}; pinned block {pin} ({block_hash[:18]}…)")

        def forge_test(match_contract: str, log_path: Path, env_extra: dict):
            log_path.parent.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ, **env_extra)
            with open(log_path, "w", encoding="utf-8") as lf:
                run(["forge", "test", "--match-contract", match_contract,
                     "--fork-url", rpc, "--fork-block-number", str(pin), "-vvv"],
                    cwd=DEMO, env=env, check=True, stdout=lf)
            text = log_path.read_text(encoding="utf-8", errors="ignore")
            if "Suite result: ok" not in text and "suite result: ok" not in text.lower():
                raise SystemExit(f"{match_contract} failed; see {log_path}")
            return text

        say("running both PoCs against the pinned local fork")
        run_dir = DEMO / "run"
        exploit_log = run_dir / "exploit-run.log"
        refute_log = run_dir / "refute-run.log"
        forge_test("ExploitVaultTest", exploit_log, {"VAULT_ADDR": vault})
        forge_test("RefuteGuardedTest", refute_log, {"GUARDED_ADDR": guarded})
        for marker, log in (("ProfitWithdrawn", exploit_log), ("RESULT: REFUTED", refute_log)):
            if marker not in log.read_text(encoding="utf-8", errors="ignore"):
                raise SystemExit(f"marker {marker!r} missing from {log}")

        # ------------------------------------------------------------------
        say("initializing the lifecycle case root")
        prog_src = Path(tempfile.mkdtemp(prefix="fl-prog-"))
        rules = wfile(prog_src / "rules-snapshot.md",
                      "# Demo bounty rules (frozen snapshot)\n\n"
                      "scope: demo local-chain deployments\n"
                      "impacts: direct theft of user funds\n"
                      "high: any confirmed theft of user deposits\n")
        wyaml(prog_src / "program.yaml", {
            "program": {
                "id": "demo-local-chain", "name": "Demo Local Chain Exercise",
                "rules_url": "https://example.test/demo-rules",
                "docs_url": "https://docs.example.test/security",
                "bounty_page_url": "https://platform.test/demo",
                "fetched_at": str(date.today()), "valid_until": None,
                "snapshot": {"path": "rules-snapshot.md", "sha256": None},
            },
            "scope": {
                "chains": [31337],
                "targets": [
                    {"address": vault, "role": "primary", "note": "VulnerableVault"},
                    {"address": guarded, "role": "peripheral", "note": "GuardedVault"},
                ],
                "assets": ["ETH"], "impacts_allowed": ["loss-of-funds"],
            },
            "severity_matrix": [
                {"id": "S1", "level": "CRITICAL", "text": "drain of all user funds", "basis": "demo rules"},
                {"id": "S2", "level": "HIGH", "text": "direct theft of user deposits", "basis": "demo rules"},
            ],
            "exclusions": [{"id": "E1", "category": "privileged",
                            "text": "issues requiring privileged roles are excluded"}],
            "novelty_sources": [{"source": "official-audits", "location": None, "status": "missing"}],
            "bounty": {"currency": "ETH", "ranges": "high: 5-10 ETH", "min_accepted_payout": None},
            "submission_limits": {"accounts": ["demo-account"], "counting": "per 14 days",
                                  "window": None, "max_per_window": 3, "timezone": "UTC"},
            "delivery": {"language": "en", "fields": ["summary", "severity", "PoC", "impact"],
                         "attachments": "zip PoC package via private attachment",
                         "private_channels": ["platform private portal", "private repo"]},
            "kyc": {"required": "NOT_REQUIRED"},
            "response": {"sla": "first triage within 48h",
                         "appeal": {"method": "portal", "deadline_days": 14}},
        })
        lc(case_root, "init", "--program-yaml", prog_src / "program.yaml",
           "--rules-snapshot", rules)

        # ------------------------------------------------------------------
        say("FINDING A (success case): register + advance to SUBMITTED")
        fidA = register(case_root,
                        "Reentrancy in VulnerableVault.withdraw drains all deposits",
                        "withdraw() sends ETH before clearing balances, so a reentrant "
                        "receiver drains the vault including the victim seed",
                        "SCAN-001")
        evA = case_root / "evidence" / fidA
        print(f"  finding A: {fidA}")

        # stage 1: prior art — official channels have no published audits
        wyaml(evA / "prior-art.yaml", {
            "discovery": [
                {"kind": "docs_site", "url": "https://docs.example.test/security",
                 "fetched_at": str(date.today()), "note": "no audits section"},
                {"kind": "program_page", "url": "https://platform.test/demo",
                 "fetched_at": str(date.today()), "note": "no audit links listed"},
            ],
            "reports": [], "checks": [],
            "no_reports_found": True,
            "no_reports_note": "docs site and program page list no audit reports for this demo program",
            "conclusion": "NEW",
        })
        advance(case_root, fidA, "demo-agent",
                "checked docs site and program page for published audits; none exist")

        # stage 2: cross-check
        wfile(evA / "assessment.md",
              "# Assessment\n\n## Deployment & reachability\n"
              f"- VulnerableVault at {vault} (chain 31337, runtime bytecode hash "
              f"{hashlib.sha256(code_vault.encode()).hexdigest()[:16]}…), verified via cast code.\n"
              "- GuardedVault shares the withdraw shape but is hardened (see finding B).\n\n"
              "## Root cause & failure mechanism\n"
              "- withdraw() performs the external call before balances[msg.sender] = 0.\n\n"
              "## Refutation attempts\n"
              "- reentrancy guarded variant? not this deployment — no nonReentrant modifier in runtime.\n"
              "- only reachable with huge stake? no — any deposit size reenters.\n\n"
              "## Impact & economics\n"
              f"- victim seed {SEED_ETH} ETH fully extractable; attacker profit = seed (own stake returned).\n\n"
              "## Adverse evidence\n"
              "- none; the attack uses no cheatcode powers.\n")
        wyaml(evA / "cross-check.yaml", {
            "targets": [{
                "chain_id": 31337, "address": vault,
                "proxy_address": None, "implementation_address": None,
                "block": pin,
                "code_sha256": "0x" + hashlib.sha256(code_vault.encode()).hexdigest(),
            }],
            "root_cause": {"claim": "external call precedes state update in withdraw()",
                           "variants": []},
            "refutation_attempts": [
                {"attempt": "check for a reentrancy guard in the runtime bytecode",
                 "outcome": "no nonReentrant pattern present on this deployment"},
                {"attempt": "check whether withdrawal is owner-restricted",
                 "outcome": "withdraw() is permissionless"},
            ],
            "damage_vs_profit": {
                "victim_damage": f"{SEED_ETH} ETH seeded funds fully drained",
                "attacker_profit": f"{SEED_ETH} ETH net (stake returned, gas unknown)",
            },
            "assessment": f"evidence/{fidA}/assessment.md",
            "uncovered_variants": [],
        })
        advance(case_root, fidA, "demo-agent",
                f"deployment variants verified; refutations documented in evidence/{fidA}/assessment.md")

        # stage 3: fork proof (real pinned-fork run)
        shutil.copyfile(DEMO / "test" / "ExploitVault.t.sol", evA / "ExploitVault.t.sol")
        shutil.copyfile(exploit_log, evA / "run.log")
        wyaml(evA / "fork-proof.yaml", {
            "fork": {"chain_id": 31337, "block_number": pin, "block_hash": block_hash,
                     "rpc_url_ref": "env DEMO_RPC_URL (local anvil)",
                     "tool_versions": {"forge": forge_version}},
            "targets_checked": [vault],
            "capabilities": [],
            "controls": [
                {"control": "pause", "applicable": False,
                 "verified": "no pause function exists on the deployment"},
                {"control": "denylist", "applicable": False,
                 "verified": "no denylist storage layout present"},
            ],
            "poc": {
                "test_file": f"evidence/{fidA}/ExploitVault.t.sol",
                "run_log": f"evidence/{fidA}/run.log",
                "expected_assertions": ["ProfitWithdrawn"],
                "result": "PASS",
            },
            "pnl": {
                "currency": "ETH",
                "attacker": [
                    {"item": "gross_proceeds", "amount": f"{SEED_ETH + STAKE_ETH} ETH (incl. stake)", "known": True},
                    {"item": "net_profit", "amount": f"{SEED_ETH} ETH", "known": True},
                    {"item": "gas", "amount": "unknown", "known": False},
                ],
                "victim": [{"item": "seeded_funds_lost", "amount": f"{SEED_ETH} ETH", "known": True}],
            },
        })
        advance(case_root, fidA, "demo-agent",
                f"exploit reproduced on the pinned fork; assertions in evidence/{fidA}/run.log")

        # stage 4: triage
        wyaml(evA / "triage.yaml", {
            "severity": {"final": "HIGH", "matrix_entry": "S2",
                         "justification": f"net profit {SEED_ETH} ETH matches S2 (theft of deposits) per evidence/{fidA}/run.log"},
            "eligibility": [
                {"aspect": "scope", "rule_ref": "rules-snapshot.md#scope", "status": "PASS",
                 "evidence": f"evidence/{fidA}/run.log", "explanation": "target in scope list"},
                {"aspect": "E1 privileged", "rule_ref": "rules-snapshot.md#E1", "status": "PASS",
                 "evidence": f"evidence/{fidA}/assessment.md",
                 "explanation": "attack requires no privileged role"},
            ],
            "novelty": {
                "sources_searched": [
                    {"source": "official audits (PRIOR_ART_CHECKED)",
                     "result": "no published audits exist", "location": f"evidence/{fidA}/prior-art.yaml"},
                ],
                "known_issues_found": "none",
                "missing_materials": ["era map not published for the demo program"],
            },
            "program_snapshot": {"sha256": sha(case_root / "rules-snapshot.md")},
        })
        advance(case_root, fidA, "demo-agent",
                f"eligibility PASS; severity justified by evidence/{fidA}/run.log amounts")

        # stage 5: package
        pkg = case_root / "packages" / fidA
        pkg.mkdir(parents=True)
        wfile(pkg / "report.en.md",
              "# Reentrancy in VulnerableVault.withdraw drains all deposits\n\n"
              "**Program:** demo-local-chain  \n"
              f"**Severity claimed:** HIGH (S2)  \n"
              f"**Target:** 31337 {vault}  \n"
              f"**Pinned block:** {pin} ({block_hash})\n\n"
              "## Summary\n\n"
              f"A reentrant receiver drains VulnerableVault completely; the seeded {SEED_ETH} ETH "
              "of victim funds is extracted with a 1 ETH stake and no privileged access.\n\n"
              "## Root cause\n\n"
              "`withdraw()` sends ETH via `msg.sender.call` before setting "
              "`balances[msg.sender] = 0`, so the balance can be withdrawn repeatedly.\n\n"
              "## Preconditions\n\n"
              "| # | Precondition | Available? |\n|---|---|---|\n"
              f"| 1 | {STAKE_ETH} ETH stake | yes |\n"
              "| 2 | receiver contract with a receive() hook | yes, standard |\n\n"
              "## Attack path\n\n"
              "deposit(stake) -> withdraw() -> receive() re-enters withdraw() until the vault "
              "balance drops below the stake; see `test/ExploitVault.t.sol`.\n\n"
              "## Impact\n\n"
              f"- Victim damage: {SEED_ETH} ETH seeded funds.  \n"
              f"- Attacker profit: {SEED_ETH} ETH net (stake returned); gas unknown.\n\n"
              "## Proof of concept\n\n"
              "Run `setup_and_run.sh` with `RPC_URL`, `VAULT_ADDR`, `PIN`; it forks the demo "
              "chain at the pinned block and must print `RESULT: PASS` with the "
              "`ProfitWithdrawn` assertion.\n\n"
              "## Limitations\n\n"
              "Demo target on a local chain; gas costs are not modeled.\n")
        (pkg / "test").mkdir()
        shutil.copyfile(DEMO / "test" / "ExploitVault.t.sol", pkg / "test" / "ExploitVault.t.sol")
        (pkg / "src").mkdir()
        shutil.copyfile(DEMO / "src" / "Attacker.sol", pkg / "src" / "Attacker.sol")
        shutil.copyfile(DEMO / "foundry.toml", pkg / "foundry.toml")
        wfile(pkg / "setup_and_run.sh", f"""#!/usr/bin/env bash
# Demo PoC runner: pinned toolchain; forks the demo local chain at the pinned
# block. No downloads. Declared prerequisites: forge, RPC access.
set -euo pipefail
command -v forge >/dev/null 2>&1 || {{ echo "forge not found" >&2; exit 2; }}
: "${{RPC_URL:?RPC_URL must point at the demo chain RPC}}"
: "${{VAULT_ADDR:?VAULT_ADDR required}}"
: "${{PIN:?PIN (fork block number) required}}"
LOG=run.log
forge test --match-contract ExploitVaultTest --fork-url "$RPC_URL" --fork-block-number "$PIN" -vvv | tee "$LOG"
grep -q "ProfitWithdrawn" "$LOG"
echo "RESULT: PASS"
""")
        os.chmod(pkg / "setup_and_run.sh", 0o755)
        shutil.copytree(DEMO / "lib" / "forge-std", pkg / "lib" / "forge-std",
                        ignore=shutil.ignore_patterns(".git", "out", "cache"))

        zpath = pkg / "package.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(pkg.rglob("*")):
                if p.is_file() and p.name not in ("package.zip", "manifest.yaml"):
                    zf.write(p, p.relative_to(pkg).as_posix())

        # clean-directory run of the frozen package
        say("running the package in a clean directory")
        clean = Path(tempfile.mkdtemp(prefix="fl-cleanrun-"))
        with zipfile.ZipFile(zpath) as zf:
            zf.extractall(clean)
        clean_log = evA / "clean-run.log"
        with open(clean_log, "w", encoding="utf-8") as lf:
            run(["bash", "setup_and_run.sh"], cwd=clean,
                env=dict(os.environ, RPC_URL=rpc, VAULT_ADDR=vault, PIN=str(pin)),
                check=True, stdout=lf)
        if "RESULT: PASS" not in clean_log.read_text(encoding="utf-8", errors="ignore"):
            raise SystemExit("clean run did not produce RESULT: PASS")

        files = []
        for rel in ("report.en.md", "test/ExploitVault.t.sol", "src/Attacker.sol",
                    "foundry.toml", "setup_and_run.sh"):
            files.append({"path": f"packages/{fidA}/{rel}", "sha256": sha(pkg / rel),
                          "purpose": "final-report" if rel.startswith("report") else
                                     ("poc-test" if rel.startswith("test/") else "package-file")})
        # the zip holds the package payload; manifest.yaml (with the zip hash)
        # stays outside it — that is how the PACKAGED gate verifies integrity
        wyaml(pkg / "manifest.yaml", {
            "package": {
                "report": {"path": f"packages/{fidA}/report.en.md",
                           "language": "en", "root_cause_id": "RC-1"},
                "files": files,
                "zip": {"path": f"packages/{fidA}/package.zip", "sha256": sha(zpath)},
                "clean_run": {"performed_in": str(clean),
                              "log_path": f"evidence/{fidA}/clean-run.log",
                              "result": "PASS"},
                "secrets_scan": {
                    "status": "EXCEPTIONS",
                    "exceptions": [
                        {"file": f"packages/{fidA}/report.en.md",
                         "pattern_id": "privkey_hex",
                         "reason": "false positive: the 0x-prefixed 64-hex string is the pinned "
                                   "block hash quoted in the report header, not a private key"},
                    ],
                },
                "dependencies": {
                    "pinned": [{"name": "foundry", "version": forge_version},
                               {"name": "forge-std", "version": FORGE_STD_REF.split("@")[-1]}],
                    "external_prereqs": [f"forge {forge_version}", "demo chain RPC access"],
                },
                "self_contained": True,
            },
        })
        advance(case_root, fidA, "demo-agent",
                f"clean-directory run passed; log at evidence/{fidA}/clean-run.log")

        # stage 6: independent self-review (second run, bound to the package hash)
        rerun_log = evA / "self-rerun.log"
        forge_test("ExploitVaultTest", rerun_log, {"VAULT_ADDR": vault})
        wyaml(evA / "self-review.yaml", {
            "reviewer": {"identity": "demo-reviewer-session-2", "kind": "independent_agent"},
            "package_sha256": "0x" + sha(zpath),
            "checks": {
                "rerun": {"performed": True, "result": "PASS",
                          "log_path": f"evidence/{fidA}/self-rerun.log"},
                "amounts": {"status": "VERIFIED",
                            "notes": "ProfitWithdrawn log equals report figures"},
                "preconditions": {"status": "VERIFIED",
                                  "notes": "stake-only attack; no cheatcode powers"},
                "wording": {"changes": []},
            },
            "adverse_facts": ["gas costs unmodeled; stated in report limitations"],
            "unresolved_objections": [],
        })
        advance(case_root, fidA, "demo-reviewer",
                f"independent rerun bound to package hash; log evidence/{fidA}/self-rerun.log")

        # stage 7: submission receipt + advance
        receipt = wfile(evA / "receipt.txt",
                        f"platform ack for DEMO-1001, submitted {date.today()} via private portal\n")
        wyaml(evA / "submission.yaml", {
            "platform_id": "DEMO-1001",
            "submitted_at": f"{date.today()}T12:00:00+00:00",
            "channel": {"kind": "platform_portal", "detail": "demo private portal",
                        "privacy_check": {"performed": True, "result": "PRIVATE"}},
            "package_sha256": "0x" + sha(zpath),
            "receipt": {"path": f"evidence/{fidA}/receipt.txt", "sha256": sha(receipt)},
            "account_limits": {"checked": True,
                               "result": "1 of 3 in window per manual submission ledger"},
            "kyc": {"status": "NOT_REQUIRED"},
        })
        lc(case_root, "record", "submission", "--id", fidA,
           "--expected-revision", revision(case_root, fidA))
        advance(case_root, fidA, "demo-agent",
                f"receipt verified; channel PRIVATE; receipt at evidence/{fidA}/receipt.txt")

        # ------------------------------------------------------------------
        say("FINDING B (false positive): register, then close REFUTED with fork counter-evidence")
        fidB = register(case_root,
                        "Claimed reentrancy in GuardedVault.withdraw",
                        "GuardedVault.withdraw allegedly allows reentrancy and drains deposits",
                        "SCAN-002")
        evB = case_root / "evidence" / fidB
        print(f"  finding B: {fidB}")

        wyaml(evB / "prior-art.yaml", {
            "discovery": [
                {"kind": "docs_site", "url": "https://docs.example.test/security",
                 "fetched_at": str(date.today()), "note": "no audits section"},
                {"kind": "program_page", "url": "https://platform.test/demo",
                 "fetched_at": str(date.today()), "note": "no audit links listed"},
            ],
            "reports": [], "checks": [],
            "no_reports_found": True,
            "no_reports_note": "no published audits for the demo program",
            "conclusion": "NEW",
        })
        advance(case_root, fidB, "demo-agent",
                "checked docs site and program page; no published audits exist")

        wfile(evB / "assessment.md",
              "# Assessment\n\n"
              f"- GuardedVault at {guarded} shares the withdraw shape with VulnerableVault.\n"
              "- static pass suggested reentrancy; fork attempt required before any conclusion.\n")
        wyaml(evB / "cross-check.yaml", {
            "targets": [{
                "chain_id": 31337, "address": guarded,
                "proxy_address": None, "implementation_address": None,
                "block": pin,
                "code_sha256": "0x" + hashlib.sha256(code_guarded.encode()).hexdigest(),
            }],
            "root_cause": {"claim": "alleged reentrancy in withdraw()", "variants": []},
            "refutation_attempts": [
                {"attempt": "run the reentrancy attack on the pinned fork",
                 "outcome": "see refutation run: profit zero, mechanism identified"},
            ],
            "damage_vs_profit": {
                "victim_damage": "none observed",
                "attacker_profit": "zero",
            },
            "assessment": f"evidence/{fidB}/assessment.md",
            "uncovered_variants": [],
        })
        advance(case_root, fidB, "demo-agent",
                f"claim pinned to the guarded deployment; fork attempt queued per evidence/{fidB}/assessment.md")

        ref_dir = evB / "refutation"
        ref_dir.mkdir(parents=True)
        shutil.copyfile(DEMO / "test" / "RefuteGuarded.t.sol", ref_dir / "RefuteGuarded.t.sol")
        shutil.copyfile(refute_log, ref_dir / "refute-run.log")
        lc(case_root, "close", "--id", fidB, "--disposition", "REFUTED",
           "--refutation-poc", f"evidence/{fidB}/refutation/RefuteGuarded.t.sol",
           "--refutation-log", f"evidence/{fidB}/refutation/refute-run.log",
           "--boundary",
           f"refuted on deployment {guarded} at block {pin} only: CEI ordering zeroes the "
           "balance before the transfer, so the re-entrant withdraw reverts with "
           "'nothing to withdraw'; other variants and future upgrades not covered",
           "--expected-revision", revision(case_root, fidB))

        # ------------------------------------------------------------------
        say("final state")
        lc(case_root, "resume")
        index = (case_root / "index.md").read_text(encoding="utf-8")
        print(index)
        assert "SUBMITTED" in index and "REFUTED" in index, "unexpected final index"
        say(f"demo complete — case root: {case_root}")
        return 0
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=10)
        except subprocess.TimeoutExpired:
            anvil.kill()
        anvil_log.close()


if __name__ == "__main__":
    sys.exit(main())
