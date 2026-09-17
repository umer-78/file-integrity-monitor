"""fim: build a baseline, then check a directory against it."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .core import BaselineError, build_baseline, compare, load_baseline, save_baseline, scan

DEFAULT_EXCLUDES = [".git", "__pycache__", "*.pyc", ".DS_Store", "node_modules"]
SYMBOL = {"added": "+", "removed": "-", "modified": "~", "permissions": "!"}


def _key() -> bytes | None:
    k = os.environ.get("FIM_KEY")
    return k.encode() if k else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fim", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="record a baseline")
    init.add_argument("root")
    init.add_argument("-o", "--output", default="fim-baseline.json")
    init.add_argument("-x", "--exclude", action="append", default=[], help="glob to skip")

    check = sub.add_parser("check", help="compare a directory with its baseline")
    check.add_argument("-b", "--baseline", default="fim-baseline.json")
    check.add_argument("--json", action="store_true")
    check.add_argument("-x", "--exclude", action="append", default=[])

    watch = sub.add_parser("watch", help="check repeatedly and print changes as they happen")
    watch.add_argument("-b", "--baseline", default="fim-baseline.json")
    watch.add_argument("-i", "--interval", type=float, default=10.0, help="seconds between scans")
    watch.add_argument("-x", "--exclude", action="append", default=[])

    args = ap.parse_args(argv)
    key = _key()
    try:
        if args.cmd == "init":
            base = build_baseline(args.root, DEFAULT_EXCLUDES + args.exclude)
            out = Path(args.output).resolve()
            save_baseline(base, out, key)
            signed = "signed" if key else "unsigned (set FIM_KEY to sign it)"
            print(f"Baseline of {len(base.files)} files written to {out}, {signed}.")
            return 0

        base = load_baseline(args.baseline, key)
        excludes = DEFAULT_EXCLUDES + args.exclude + [Path(args.baseline).name]
        if args.cmd == "check":
            changes = compare(base, scan(Path(base.root), excludes))
            if args.json:
                print(json.dumps([c.__dict__ for c in changes], indent=2))
            elif not changes:
                print(f"OK: {len(base.files)} files unchanged since {base.created_at}")
            else:
                for c in changes:
                    print(f"{SYMBOL[c.kind]} {c.kind:12} {c.path}  {c.detail}".rstrip())
                print(f"{len(changes)} change(s).")
            return 1 if changes else 0

        seen: set = set()
        print(f"Watching {base.root} every {args.interval:g}s. Ctrl+C to stop.")
        while True:
            for c in compare(base, scan(Path(base.root), excludes)):
                if c not in seen:
                    seen.add(c)
                    stamp = time.strftime("%H:%M:%S")
                    print(f"{stamp} {SYMBOL[c.kind]} {c.kind:12} {c.path}  {c.detail}".rstrip(),
                          flush=True)
            time.sleep(args.interval)
    except BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
