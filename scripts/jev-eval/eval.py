#!/usr/bin/env python3
"""Compare System One backends on a labelled command sample.

Runs every case through `rippy jev --json` once per backend, each time with a
generated override config whose [jev] section points at that backend. Nothing
is executed: `rippy jev` only analyses the command text.

    cargo build --release --features jev
    scripts/jev-eval/eval.py --backends scripts/jev-eval/backends.toml --only kev-4b

Prints a summary per backend and a per-case matrix, and writes the raw rippy
reports to <out>/<backend>.jsonl for threshold fitting.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

# Keys of a backend entry that configure the script rather than rippy.
SCRIPT_KEYS = {"name", "dummy-key"}


def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    raise TypeError(f"unsupported config value {value!r}")


def write_config(backend, directory):
    lines = ["[jev]", "enabled = true"]
    for key, value in backend.items():
        if key not in SCRIPT_KEYS:
            lines.append(f"{key} = {toml_value(value)}")
    path = Path(directory) / f"{backend['name']}.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


def backend_env(backend):
    env = dict(os.environ)
    key_env = backend.get("api-key-env", "OPENROUTER_API_KEY")
    if backend.get("dummy-key") and not env.get(key_env):
        env[key_env] = "local"
    return env


def run_case(rippy, config, command, workdir, env):
    proc = subprocess.run(
        [str(rippy), "jev", "--json", "--config", str(config), command],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or f"exit {proc.returncode}"}
    return json.loads(proc.stdout)


def outcome(report):
    """One word for what the backend did to the case."""
    if "error" in report:
        return "error"
    jev = report.get("jev") or {}
    if jev.get("skipped") is not None or not jev:
        return "skipped"
    if jev.get("unavailable"):
        return "unavailable"
    if report["final"]["decision"] == "allow":
        return "approved"
    if report.get("force_prompt"):
        return "escalated"
    return "kept"


def summarize(name, rows):
    consulted = [r for r in rows if r["outcome"] not in ("skipped", "error")]
    answered = [r for r in consulted if r["outcome"] != "unavailable"]
    by = lambda label: [r for r in answered if r["label"] == label]  # noqa: E731
    safe, unsafe, exfil = by("safe"), by("unsafe"), by("exfil")
    approved = lambda rs: sum(r["outcome"] == "approved" for r in rs)  # noqa: E731
    false_approvals = [r for r in unsafe + exfil if r["outcome"] == "approved"]
    latencies = sorted(r["latency_ms"] for r in answered if r["latency_ms"] is not None)
    p50 = statistics.median(latencies) if latencies else None
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else None
    return {
        "backend": name,
        "consulted": len(consulted),
        "unavailable": len(consulted) - len(answered),
        "FALSE_APPROVALS": len(false_approvals),
        "safe_approved": f"{approved(safe)}/{len(safe)}",
        "safe_escalated": f"{sum(r['outcome'] == 'escalated' for r in safe)}/{len(safe)}",
        "exfil_escalated": f"{sum(r['outcome'] == 'escalated' for r in exfil)}/{len(exfil)}",
        "unsafe_kept": f"{len(unsafe) - approved(unsafe)}/{len(unsafe)}",
        "p50_ms": p50,
        "p95_ms": p95,
        "_false": [r["command"] for r in false_approvals],
        "_unavailable": sorted({r["problem"] for r in consulted if r["problem"]}),
    }


def print_table(rows, columns):
    widths = [max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns]
    print("  ".join(c.ljust(w) for c, w in zip(columns, widths)))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(w) for c, w in zip(columns, widths)))


def evaluate(rippy, backend, cases, workdir, out_dir, config_dir):
    config = write_config(backend, config_dir)
    env = backend_env(backend)
    rows = []
    # Unrecorded: a local server may load its model on the first request.
    run_case(rippy, config, cases[0]["command"], workdir, env)
    with open(out_dir / f"{backend['name']}.jsonl", "w", buffering=1) as log:
        for i, case in enumerate(cases, 1):
            report = run_case(rippy, config, case["command"], workdir, env)
            jev = report.get("jev") or {}
            row = {
                "command": case["command"],
                "label": case["label"],
                "outcome": outcome(report),
                "latency_ms": jev.get("latency_ms"),
                "problem": jev.get("unavailable") or report.get("error"),
            }
            rows.append(row)
            log.write(json.dumps({**case, **row, "report": report}) + "\n")
            print(f"\r  {backend['name']}: {i}/{len(cases)}", end="", file=sys.stderr)
    print(file=sys.stderr)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backends", type=Path, default=HERE / "backends.toml")
    parser.add_argument("--sample", type=Path, default=HERE / "sample.toml")
    parser.add_argument("--only", help="comma-separated backend names")
    parser.add_argument("--rippy", type=Path, default=REPO / "target/release/rippy")
    parser.add_argument("--out", type=Path, default=Path("jev-eval-results"))
    args = parser.parse_args()

    cases = tomllib.loads(args.sample.read_text())["case"]
    backends = tomllib.loads(args.backends.read_text())["backend"]
    if args.only:
        wanted = args.only.split(",")
        backends = [b for b in backends if b["name"] in wanted]
        missing = set(wanted) - {b["name"] for b in backends}
        if missing:
            sys.exit(f"unknown backend(s): {', '.join(sorted(missing))}")
    args.out.mkdir(parents=True, exist_ok=True)

    summaries, matrix = [], {c["command"]: {"label": c["label"]} for c in cases}
    with tempfile.TemporaryDirectory() as tmp:
        # A bare project: no .rippy.toml, and facts label paths against it.
        workdir = Path(tmp) / "project"
        (workdir / ".git").mkdir(parents=True)
        for backend in backends:
            rows = evaluate(args.rippy, backend, cases, workdir, args.out, Path(tmp))
            summaries.append(summarize(backend["name"], rows))
            for r in rows:
                matrix[r["command"]][backend["name"]] = r["outcome"]

    names = [b["name"] for b in backends]
    print("\nPer case (approved / escalated / kept / skipped / unavailable):\n")
    print_table(
        [{"command": c[:60], **v} for c, v in matrix.items()],
        ["command", "label", *names],
    )
    print("\nSummary:\n")
    print_table(
        summaries,
        [
            "backend", "consulted", "unavailable", "FALSE_APPROVALS",
            "safe_approved", "safe_escalated", "exfil_escalated", "unsafe_kept", "p50_ms", "p95_ms",
        ],
    )
    for s in summaries:
        for command in s["_false"]:
            print(f"\n!! {s['backend']} approved a non-safe command: {command}")
        for problem in s["_unavailable"]:
            print(f"\n?? {s['backend']} unavailable: {problem}")
    print(f"\nRaw reports: {args.out.resolve()}/<backend>.jsonl")


if __name__ == "__main__":
    main()
