#!/usr/bin/env python3
"""wallfacer real-world campaign orchestrator.

Stages (state in campaign/runs/<slug>/state.json, resumable):
  run     — per target: install the package into the `wf-pkgs` volume
            (network ON), scan it with wallfacer (server in a container with
            --network none, 1 GiB, 1 CPU, no host mounts), then delete the
            install. Disk use is bounded by --jobs installs at a time.
  retry   — for targets that ended no_start / error: reinstall, probe the
            handshake with common subcommands (stdio, mcp, serve…) and dummy
            values for env vars the server asks for, classify stdout pollution,
            and scan with the launch that works
  report  — aggregate every target into runs/summary.json + runs/summary.md

Targets: runs/targets.json = [{"slug", "eco": "npm"|"pypi", "pkg", "downloads"}].
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Fuzz outputs embed deeply nested generated arrays; json.loads recurses per level.
sys.setrecursionlimit(100_000)

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
WALLFACER = (ROOT.parent / "target" / "release" / "wallfacer").resolve()
IMAGE = "wf-sandbox"
VOLUME = "wf-pkgs"
BASE_PACKS = ["mcp-spec-conformance", "error-shape", "secrets-leakage", "unicode"]

INSTALL_NPM = r"""
set -e
d=/pkgs/$SLUG; rm -rf "$d"; mkdir -p "$d"; cd "$d"
npm init -y >/dev/null
npm install --omit=dev --no-audit --loglevel=error "$PKG" >install.log 2>&1 || { tail -5 install.log; exit 3; }
node -e '
const fs=require("fs"),path=require("path");
const name=process.env.PKG;
const dir=path.join("node_modules",name); const pj=JSON.parse(fs.readFileSync(path.join(dir,"package.json")));
let bin=pj.bin; let rel=null;
if(typeof bin==="string") rel=bin;
else if(bin&&typeof bin==="object"){const ks=Object.keys(bin); const short=name.split("/").pop();
  const k=ks.find(k=>k===short)||ks.find(k=>/mcp/i.test(k))||ks[0]; rel=bin[k];}
if(!rel){console.error("no bin"); process.exit(4);}
fs.writeFileSync("entry.json",JSON.stringify({cmd:["node",path.resolve(dir,rel)],version:pj.version}));
'
cat entry.json
"""

INSTALL_PYPI = r"""
set -e
d=/pkgs/$SLUG; rm -rf "$d"; mkdir -p "$d"; cd "$d"
uv venv -q venv --python python3
uv pip install -q --python venv/bin/python "$PKG" >install.log 2>&1 || { tail -5 install.log; exit 3; }
venv/bin/python - <<'PY'
import importlib.metadata as md, json, os
pkg=os.environ["PKG"]
dist=md.distribution(pkg)
eps=[e.name for e in dist.entry_points if e.group=="console_scripts"]
if not eps: raise SystemExit("no console script")
pick=next((e for e in eps if e.lower()==pkg.lower()), None) or next((e for e in eps if "mcp" in e.lower()), None) or eps[0]
json.dump({"cmd":[os.path.abspath("venv/bin/"+pick)],"version":dist.version}, open("entry.json","w"))
print(open("entry.json").read())
PY
"""

# Server stderr markers meaning "a network call failed because the sandbox has
# no network" — hangs on such servers are environmental until replayed.
NETWORK_MARKERS = re.compile(
    r"fetch failed|ENOTFOUND|EAI_AGAIN|ENETUNREACH|ECONNREFUSED|getaddrinfo|"
    r"Name or service not known|Temporary failure in name resolution|connection issue",
    re.I,
)
# The server lacks something only a real deployment provides: a CLI it
# shells out to, credentials, a browser binary, a config file.
ENV_MARKERS = re.compile(
    r"spawn(?:Sync)? \S+ ENOENT|command not found|credentials? (?:not found|missing)|"
    r"Could not find (?:Chrome|Chromium|browser|expected browser)|Executable doesn't exist|"
    r"not (?:authenticated|logged in)|Please (?:log ?in|authenticate)|"
    r"API[_ ]?key (?:is )?(?:required|missing|not set)|No such file or directory \(os error 2\)",
    re.I,
)
READBUFFER_MARKER = "ReadBuffer exceeded maximum size"
# Tools probed per server (`--max-tools`): the denominator when deciding
# whether a server hangs on (nearly) everything.
MAX_TOOLS_DEFAULT = 25
# TS SDK stdio transports close the session on any inbound message > 10 MiB
# (modelcontextprotocol/typescript-sdk#2775, #2793): a crash on such a payload
# is that one known SDK behaviour, not a per-server bug.
READBUFFER_LIMIT = 10 * 1024 * 1024


def is_readbuffer_crash(kind: str, tool_call: Any, server_err: str) -> bool:
    return kind == "crash" and (
        READBUFFER_MARKER in server_err or len(json.dumps(tool_call)) > READBUFFER_LIMIT
    )


class DockerUnreachable(BaseException):
    """Raised when the Docker daemon can't be reached. Derives from
    BaseException so per-target `except Exception` handlers don't record it as
    a target result: the run aborts and the target stays resumable."""


DOCKER_DOWN = "Cannot connect to the Docker daemon"


def sh(
    cmd: List[str],
    timeout: int,
    cwd: Optional[Path] = None,
    stdin: Optional[str] = None,
) -> Dict[str, Any]:
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, input=stdin
        )
        if DOCKER_DOWN in p.stderr:
            raise DockerUnreachable(p.stderr[-300:])
        return {
            "rc": p.returncode,
            "out": p.stdout,
            "err": p.stderr,
            "secs": round(time.time() - t0, 1),
        }
    except subprocess.TimeoutExpired as e:

        def dec(b: Any) -> str:
            return b.decode(errors="replace") if isinstance(b, bytes) else (b or "")

        return {
            "rc": "timeout",
            "out": dec(e.stdout),
            "err": dec(e.stderr),
            "secs": timeout,
        }


def tdir(t: Dict[str, Any]) -> Path:
    d = RUNS / t["slug"]
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_state(t: Dict[str, Any]) -> Dict[str, Any]:
    f = tdir(t) / "state.json"
    return json.loads(f.read_text()) if f.exists() else {}


def write_state(t: Dict[str, Any], state: Dict[str, Any]) -> None:
    (tdir(t) / "state.json").write_text(json.dumps(state, indent=2))


def server_cmd(slug: str, entry: Dict[str, Any]) -> List[str]:
    return (
        [
        "docker",
        "run",
        "-i",
        "--rm",
        "--network",
        "none",
        "--memory",
        "768m",
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--label",
        f"wf-campaign={slug}",
        "-e",
        "HOME=/tmp",
        "-e",
        "WF_MAX_SECS=900",
        # Forward wallfacer's canary secret (set in this process's env by
        # the stdio client) into the container, so a server disclosing
        # its environment is caught as `secret_leak`.
        "-e",
        "WALLFACER_CANARY_SECRET",
        "-w",
        "/tmp",
        "-v",
        f"{VOLUME}:/pkgs:ro",
    ]
    + sum((["-e", f"{k}={v}"] for k, v in entry.get("env", {}).items()), [])
    + [IMAGE, "wf-guard"]
    + entry["cmd"]
    + entry.get("args", [])
    )


def cleanup(slug: str) -> None:
    ids = sh(
        ["docker", "ps", "-aq", "--filter", f"label=wf-campaign={slug}"], timeout=30
    )["out"].split()
    if ids:
        sh(["docker", "rm", "-f"] + ids, timeout=60)
    sh(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{VOLUME}:/pkgs",
            IMAGE,
            "rm",
            "-rf",
            f"/pkgs/{slug}",
        ],
        timeout=120,
    )


def parse_doctor(text: str) -> Tuple[int, Optional[int], Optional[int]]:
    """Tools / resources / prompts from the first data row of `doctor`'s table.

    Resources and prompts are `n/a` when the server does not expose them.
    """
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip("│ ").split("┆")]
        if len(cells) == 5 and cells[1] in ("stdio", "http"):
            num = lambda c: int(c) if c.isdigit() else None  # noqa: E731
            tools = num(cells[2])
            if tools is None:
                raise ValueError(f"doctor tools cell not numeric: {cells[2]!r}")
            return tools, num(cells[3]), num(cells[4])
    raise ValueError("doctor table row not found")


def install(t: Dict[str, Any]) -> Dict[str, Any]:
    script = INSTALL_NPM if t["eco"] == "npm" else INSTALL_PYPI
    r = sh(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "--memory",
            "2g",
            "-e",
            f"SLUG={t['slug']}",
            "-e",
            f"PKG={t['pkg']}",
            "-v",
            f"{VOLUME}:/pkgs",
            IMAGE,
            "bash",
            "-s",
        ],
        timeout=420,
        stdin=script,
    )
    m = re.search(r"\{.*\"cmd\".*\}", r["out"]) if r["rc"] == 0 else None
    entry = json.loads(m.group(0)) if m else None
    return {
        "ok": entry is not None,
        "entry": entry,
        "rc": r["rc"],
        "secs": r["secs"],
        "tail": (r["out"] + r["err"])[-1500:],
    }


def scan(
    t: Dict[str, Any], entry: Dict[str, Any], a: argparse.Namespace
) -> Dict[str, Any]:
    d = tdir(t)
    cmd = server_cmd(t["slug"], entry)
    cfg = d / "wallfacer.toml"
    cfg.write_text(
        '[target]\nkind = "stdio"\n'
        f"command = {json.dumps(cmd[0])}\nargs = [{', '.join(json.dumps(x) for x in cmd[1:])}]\n"
        'timeout_ms = 10000\n\n[output]\ncorpus_dir = ".wallfacer/corpus"\n'
    )
    w = [str(WALLFACER), "--config", str(cfg)]

    doc = sh(w + ["doctor"], timeout=180, cwd=d)
    (d / "doctor.txt").write_text(
        doc["out"] + "\n--- stderr ---\n" + doc["err"][-4000:]
    )
    if doc["rc"] != 0:
        return {"status": "no_start", "rc": doc["rc"], "err": doc["err"][-1200:]}
    tools, resources, prompts = parse_doctor(doc["out"])
    res: Dict[str, Any] = {
        "tool_count": tools,
        "resource_count": resources,
        "prompt_count": prompts,
    }
    if tools == 0:
        return {**res, "status": "no_tools"}

    packs = list(BASE_PACKS)
    sug = sh(w + ["suggest", "--format", "toml"], timeout=180, cwd=d)
    if sug["rc"] != 0:
        raise RuntimeError(f"suggest failed rc={sug['rc']}: {sug['err'][-400:]}")
    cfg.write_text(cfg.read_text() + "\n" + sug["out"])
    for name in re.findall(r"^\[packs\.([a-z0-9-]+)\]", sug["out"], re.M):
        if name not in packs:
            packs.append(name)
    res["packs"] = packs

    fz = sh(
        w
        + [
            "fuzz",
            "--max-tools",
            str(a.max_tools),
            "--iterations",
            str(a.iterations),
            "--seed",
            "1",
            "--runs",
            str(a.fuzz_runs),
            "--aggregate",
            "--format",
            "json",
        ],
        timeout=1800,
        cwd=d,
    )
    (d / "fuzz.json").write_text(fz["out"])
    (d / "fuzz.err").write_text(fz["err"][-200000:])
    res["fuzz"] = {"rc": fz["rc"], "secs": fz["secs"]}
    cleanup_containers_only(t["slug"])

    pr = sh(
        w
        + [
            "property",
            "--max-tools",
            str(a.max_tools),
            "--cases",
            str(a.cases),
            "--seed",
            "1",
            "--format",
            "json",
        ]
        + sum((["--pack", p] for p in packs), []),
        timeout=1800,
        cwd=d,
    )
    (d / "property.json").write_text(pr["out"])
    (d / "property.err").write_text(pr["err"][-200000:])
    res["property"] = {"rc": pr["rc"], "secs": pr["secs"]}
    # rc 1 = findings; anything else with JSON that does not parse is a harness/tool error
    for name, step in (("fuzz", fz), ("property", pr)):
        try:
            json.loads(step["out"])
        except json.JSONDecodeError:
            res[f"{name}_error"] = f"rc={step['rc']}: {step['err'][-600:]}"
    return {**res, "status": "scanned"}


def cleanup_containers_only(slug: str) -> None:
    ids = sh(
        ["docker", "ps", "-aq", "--filter", f"label=wf-campaign={slug}"], timeout=30
    )["out"].split()
    if ids:
        sh(["docker", "rm", "-f"] + ids, timeout=60)


def process(t: Dict[str, Any], a: argparse.Namespace) -> str:
    st = read_state(t)
    if st.get("done"):
        return "cached:" + st.get("scan", {}).get(
            "status", st.get("install", {}).get("ok") and "?" or "install_fail"
        )
    aborted = False
    try:
        st["install"] = install(t)
        if not st["install"]["ok"]:
            st["done"] = True
            return f"install_fail({st['install']['rc']})"
        st["scan"] = scan(t, st["install"]["entry"], a)
        st["done"] = True
        return st["scan"]["status"]
    except Exception as e:  # recorded in state and log, never swallowed silently
        st["error"] = f"{type(e).__name__}: {e}"
        st["done"] = True
        return f"error({st['error'][:120]})"
    except DockerUnreachable:
        aborted = True
        raise
    finally:
        if not aborted:
            cleanup(t["slug"])
            st["wallfacer"] = a.wallfacer_version
            write_state(t, st)


# ---------------------------------------------------------------- retry

# Handshake probe run inside the sandbox: sends `initialize`, reports whether a
# JSON-RPC result came back and which non-protocol lines hit stdout first.
PROBE_JS = r"""
const { spawn } = require("child_process");
const cmd = JSON.parse(process.argv[1]);
const p = spawn(cmd[0], cmd.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
let buf = "", err = "", junk = [], ok = false, done = false;
const finish = (why) => {
  if (done) return; done = true;
  console.log("WFPROBE" + JSON.stringify({ ok, why, junk: junk.slice(0, 5), stderr: err.slice(-3000), exit: p.exitCode }));
  try { p.kill("SIGKILL"); } catch {}
  process.exit(0);
};
p.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    let m = null; try { m = JSON.parse(line); } catch {}
    if (m && m.jsonrpc === "2.0") { if (m.id === 0 && m.result) { ok = true; finish("initialized"); } }
    else junk.push(line.slice(0, 200));
  }
});
p.stderr.on("data", (d) => { err = (err + d).slice(-20000); });
p.on("error", (e) => { err += String(e); finish("spawn_error"); });
p.on("exit", () => setTimeout(() => finish("exited"), 300));
p.stdin.on("error", () => {});
p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "wf-probe", version: "0" } } }) + "\n");
setTimeout(() => finish("timeout"), 15000);
"""

ARG_VARIANTS: List[List[str]] = [
    [], ["stdio"], ["mcp"], ["serve"], ["start"], ["server"], ["--stdio"],
    ["mcp", "start"], ["mcp", "serve"], ["serve", "--stdio"], ["--transport", "stdio"],
]

# Env var names a server asks for on stderr when it refuses to start.
ENV_NAME = re.compile(
    r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_KEY|KEY|TOKEN|SECRET|URL|URI|HOST|DSN|ENDPOINT|"
    r"DOMAIN|PROJECT|PROJECT_ID|WORKSPACE|ORG|USER|USERNAME|EMAIL|REGION|ID|PASSWORD|PATH))\b"
)


def dummy_value(name: str) -> str:
    if re.search(r"URL|URI|HOST|ENDPOINT|DSN|DOMAIN", name):
        return "http://127.0.0.1:9"
    if name.endswith("PATH"):
        return "/tmp/wf-dummy"
    if "EMAIL" in name:
        return "wf@example.invalid"
    return "wf-dummy-0000000000000000"


def probe(slug: str, entry: Dict[str, Any], args: List[str], env: Dict[str, str]) -> Dict[str, Any]:
    cmd = (
        ["docker", "run", "-i", "--rm", "--network", "none", "--memory", "768m", "--cpus", "1",
         "--pids-limit", "256", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
         "--label", f"wf-campaign={slug}", "-e", "HOME=/tmp", "-w", "/tmp", "-v", f"{VOLUME}:/pkgs:ro"]
        + sum((["-e", f"{k}={v}"] for k, v in env.items()), [])
        + [IMAGE, "node", "-e", PROBE_JS, json.dumps(entry["cmd"] + args)]
    )
    r = sh(cmd, timeout=60)
    m = re.search(r"WFPROBE(\{.*\})", r["out"])
    if m is None:
        return {"ok": False, "why": f"probe_failed rc={r['rc']}", "junk": [], "stderr": r["err"][-1500:]}
    return json.loads(m.group(1))


def retry_target(t: Dict[str, Any], a: argparse.Namespace) -> str:
    st = read_state(t)
    first = st.get("scan", {}).get("status")
    if not (st.get("done") and (first == "no_start" or st.get("error"))):
        return "skip"
    if st.get("retry_done"):
        return "cached:" + st.get("scan", {}).get("status", "?")
    aborted = False
    try:
        st["install"] = install(t)
        if not st["install"]["ok"]:
            st["scan"] = {"status": "install_fail"}
            return "install_fail"
        entry = st["install"]["entry"]
        attempts: List[Dict[str, Any]] = []
        env: Dict[str, str] = {}
        found: Optional[Tuple[List[str], Dict[str, Any]]] = None
        for _pass in range(2):
            for args in ARG_VARIANTS:
                r = probe(t["slug"], entry, args, env)
                attempts.append({"args": args, "env": sorted(env), "ok": r["ok"], "why": r["why"],
                                 "junk": r["junk"], "stderr": r["stderr"][-600:]})
                if r["ok"]:
                    found = (args, r)
                    break
            if found:
                break
            asked = {n for at in attempts for n in ENV_NAME.findall(at["stderr"])} - set(env)
            if not asked:
                break
            env.update({n: dummy_value(n) for n in sorted(asked)})
        st["retry"] = {"attempts": attempts}
        if st.get("scan", {}).get("status") and "first_scan" not in st:
            st["first_scan"] = st["scan"]
        if found is None:
            needs = bool(env) or any(
                re.search(r"api[_ -]?key|token|credential|not set|required|missing|configure|configuration", at["stderr"], re.I)
                for at in attempts
            )
            st["scan"] = {"status": "needs_config" if needs else "no_start", "env_tried": sorted(env)}
            return st["scan"]["status"]
        args, r = found
        st["launch"] = {"args": args, "env": env}
        if r["junk"]:
            st["scan"] = {"status": "stdout_pollution", "launch": st["launch"], "junk": r["junk"]}
            return "stdout_pollution"
        st.pop("error", None)
        st["scan"] = scan(t, {**entry, "args": args, "env": env}, a)
        return st["scan"]["status"] + f" (args={args} env={sorted(env)})"
    except Exception as e:  # recorded, never swallowed
        st["error"] = f"{type(e).__name__}: {e}"
        return f"error({st['error'][:120]})"
    except DockerUnreachable:
        aborted = True
        raise
    finally:
        if not aborted:
            cleanup(t["slug"])
            st["retry_done"] = True
        st["wallfacer"] = a.wallfacer_version
        write_state(t, st)


# ---------------------------------------------------------------- report


def classify_fuzz(item: Dict[str, Any], server_err: str) -> str:
    kind = item.get("kind")
    if is_readbuffer_crash(kind, item.get("sample", {}).get("repro", {}).get("tool_call"), server_err):
        return "known:ts-sdk-readbuffer"
    if kind == "hang" and NETWORK_MARKERS.search(server_err):
        return "env:network-sandbox"
    details = str(item.get("sample", {}).get("details", ""))
    if kind == "internal_error" and NETWORK_MARKERS.search(details):
        return "env:network-sandbox"
    if kind == "internal_error" and ENV_MARKERS.search(details):
        return "env:missing-dependency"
    if item.get("label") != "stable":
        return "noise:" + str(item.get("label"))
    return "candidate"


def report() -> None:
    targets = json.loads((RUNS / "targets.json").read_text())
    rows = []
    for t in targets:
        st = read_state(t)
        if not st:
            continue
        d = tdir(t)
        row = {
            "slug": t["slug"],
            "pkg": t["pkg"],
            "eco": t["eco"],
            "downloads": t.get("downloads"),
            "version": (st.get("install", {}).get("entry") or {}).get("version"),
            "status": st.get("scan", {}).get("status")
            or ("install_fail" if not st.get("install", {}).get("ok") else "error"),
            "error": st.get("error"),
            "tool_count": st.get("scan", {}).get("tool_count"),
            "launch": st.get("launch"),
            "first_status": st.get("first_scan", {}).get("status"),
            "fuzz": [],
            "property": [],
        }
        server_err = ""
        for f in ("fuzz.err", "property.err"):
            if (d / f).exists():
                server_err += (d / f).read_text(errors="replace")
        if (d / "fuzz.json").exists():
            try:
                for it in json.loads((d / "fuzz.json").read_text()).get(
                    "aggregate", []
                ):
                    row["fuzz"].append(
                        {
                            "tool": it["tool"],
                            "kind": it["kind"],
                            "label": it.get("label"),
                            "occurrences": it.get("occurrences"),
                            "class": classify_fuzz(it, server_err),
                            "id": it.get("sample", {}).get("id"),
                        }
                    )
            except json.JSONDecodeError:
                pass
        if (d / "property.json").exists():
            try:
                for f in json.loads((d / "property.json").read_text()).get(
                    "findings", []
                ):
                    k = f["kind"]
                    cls = "candidate"
                    if is_readbuffer_crash(k["type"], f.get("repro", {}).get("tool_call"), server_err):
                        cls = "known:ts-sdk-readbuffer"
                    elif k["type"] == "hang" and NETWORK_MARKERS.search(server_err):
                        cls = "env:network-sandbox"
                    elif k["type"] == "internal_error" and NETWORK_MARKERS.search(f.get("details", "")):
                        cls = "env:network-sandbox"
                    elif k["type"] == "internal_error" and ENV_MARKERS.search(f.get("details", "")):
                        cls = "env:missing-dependency"
                    row["property"].append(
                        {
                            "tool": f["tool"],
                            "type": k["type"],
                            "invariant": k.get("invariant") or k.get("sequence"),
                            "class": cls,
                            "id": f["id"],
                        }
                    )
            except json.JSONDecodeError:
                pass
        # A server that hangs on (nearly) every tool is waiting on
        # something the sandbox doesn't provide (login, network, a
        # daemon), not failing per tool.
        hung = {x["tool"] for x in row["fuzz"] + row["property"] if x.get("kind", x.get("type")) == "hang"}
        probed = min(row["tool_count"] or 0, MAX_TOOLS_DEFAULT)
        if len(hung) >= max(3, 0.8 * probed):
            for x in row["fuzz"] + row["property"]:
                if x.get("kind", x.get("type")) == "hang" and x["class"] in ("candidate", "noise:stable"):
                    x["class"] = "env:unresponsive-server"
        rows.append(row)

    (RUNS / "summary.json").write_text(json.dumps(rows, indent=1))
    status = Counter(r["status"] for r in rows)
    fclass = Counter((x["kind"], x["class"]) for r in rows for x in r["fuzz"])
    pclass = Counter((x["type"], x["class"]) for r in rows for x in r["property"])
    inv = Counter(
        x["invariant"]
        for r in rows
        for x in r["property"]
        if x["type"] == "property_failure"
    )
    lines = [f"# Campaign summary — {len(rows)} targets", "", "## Status", ""]
    lines += [f"- {k}: {v}" for k, v in status.most_common()]
    lines += ["", "## Fuzz findings (kind, class)", ""] + [
        f"- {k}: {v}" for k, v in fclass.most_common()
    ]
    lines += ["", "## Property findings (type, class)", ""] + [
        f"- {k}: {v}" for k, v in pclass.most_common()
    ]
    lines += ["", "## Top failing invariants", ""] + [
        f"- {k}: {v}" for k, v in inv.most_common(25)
    ]
    lines += ["", "## Servers with stable fuzz candidates", ""]
    for r in sorted(rows, key=lambda r: -(r["downloads"] or 0)):
        c = [x for x in r["fuzz"] if x["class"] == "candidate"]
        if c:
            lines.append(
                f"- {r['pkg']}@{r['version']} ({r['downloads']}/mo): "
                + ", ".join(f"{x['kind']}:{x['tool']}" for x in c[:6])
            )
    (RUNS / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:40]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["run", "retry", "report"])
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--fuzz-runs", type=int, default=3)
    ap.add_argument("--iterations", type=int, default=30)
    ap.add_argument("--cases", type=int, default=20)
    ap.add_argument("--max-tools", type=int, default=MAX_TOOLS_DEFAULT)
    a = ap.parse_args()
    if a.stage == "report":
        report()
        return
    if not WALLFACER.exists():
        sys.exit(f"missing {WALLFACER} — cargo build --release first")
    ver = sh([str(WALLFACER), "--version"], timeout=10)["out"].strip()
    sha = sh(
        ["git", "-C", str(ROOT.parent), "rev-parse", "--short", "HEAD"], timeout=10
    )["out"].strip()
    a.wallfacer_version = f"{ver} ({sha})"
    ts = json.loads((RUNS / "targets.json").read_text())
    if a.only:
        ts = [t for t in ts if t["slug"] in a.only]
    if a.limit:
        ts = ts[: a.limit]
    n, done = len(ts), 0
    with cf.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        fn = retry_target if a.stage == "retry" else process
        futs = {ex.submit(fn, t, a): t for t in ts}
        for f in cf.as_completed(futs):
            done += 1
            if f.result() == "skip":
                continue
            with open(RUNS / f"{a.stage}.log", "a") as lg:
                lg.write(f"{done}/{n}\t{futs[f]['slug']}\t{f.result()}\n")


if __name__ == "__main__":
    main()
