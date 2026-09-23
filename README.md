# fim: file integrity monitor

[![CI](https://github.com/umer-78/file-integrity-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/umer-78/file-integrity-monitor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight host-based file integrity monitor — my small take on what
Tripwire and AIDE do. Record a **SHA-256 baseline** of a directory, then catch
files that were **added, removed, modified or had their permissions changed**.
Handy for spotting web-shell uploads, defacements and configuration drift.

```text
$ export FIM_KEY='a long random secret'
$ fim init html -o www.fim.json
Baseline of 2 files written to /home/umer/demo/www.fim.json, signed.

# ...someone uploads a web shell, defaces the page and loosens permissions...

$ fim check -b www.fim.json
+ added        uploads/shell.php  29 bytes
! permissions  config.php  0o640 → 0o666
~ modified     index.html  size 4500 → 16
3 change(s).
```

## Features

- Streaming SHA-256, so large files are fine
- Detects added, removed, modified and permission-changed files
- **Signed baselines**: with `FIM_KEY` set, the baseline carries an HMAC-SHA256.
  Editing the baseline to hide a change is detected.
- Symlinks are recorded by target and never followed
- Exclude globs (`-x '*.log' -x cache`), with sensible defaults (`.git`, `node_modules`, …)
- `watch` mode prints changes as they happen
- JSON output and exit codes for cron and CI: `0` clean, `1` changes, `3` baseline error
- Standard library only

## Install

```bash
git clone https://github.com/umer-78/file-integrity-monitor.git
cd file-integrity-monitor
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
fim init  <dir> [-o baseline.json] [-x GLOB ...]
fim check [-b baseline.json] [--json]
fim watch [-b baseline.json] [-i SECONDS]
```

Run it from cron and alert on a non-zero exit:

```cron
*/15 * * * * FIM_KEY=... /opt/fim/.venv/bin/fim check -b /root/www.fim.json || mail -s "FIM alert" you@example.com
```

## Try it

`demo/run_demo.sh` builds a small web root, takes a signed baseline, simulates a
defacement plus a web-shell upload, and then shows the signature catching an
attacker who edits the baseline itself:

```bash
bash demo/run_demo.sh
```

## Security notes

- Keep the baseline **off the monitored host**, or at least on a read-only mount,
  and keep `FIM_KEY` out of the monitored tree.
- Modification times are recorded but not compared, since they are trivial to fake.
  Content hashes are what count.
- A root-level attacker on the same host can still defeat any local monitor.
  Treat this as one layer of defence.

## Development

```bash
ruff check .
pytest -q
```

## License

[MIT](LICENSE)
