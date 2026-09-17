#!/usr/bin/env bash
# Builds a small web-root, takes a signed baseline, then simulates an attack
# (defacement, web-shell upload, loosened permissions) and re-checks it.
set -e
cd "$(dirname "$0")"
export FIM_KEY="${FIM_KEY:-demo-key-change-me}"
rm -rf sandbox && mkdir -p sandbox/html/uploads

python3 - <<'PY'
from pathlib import Path
html = Path("sandbox/html")
(html / "index.html").write_text("<h1>Welcome</h1>\n" * 300)
(html / "config.php").write_text('<?php $db = "app"; ?>\n')
(html / "uploads" / ".keep").write_text("")
PY
chmod 640 sandbox/html/config.php

echo "== baseline =="
fim init sandbox/html -o sandbox/www.fim.json

echo
echo "== no changes yet =="
fim check -b sandbox/www.fim.json

echo
echo "== simulating an attack =="
echo '<h1>hacked</h1>' > sandbox/html/index.html
printf '<?php system($_GET["c"]); ?>\n' > sandbox/html/uploads/shell.php
chmod 666 sandbox/html/config.php
fim check -b sandbox/www.fim.json || echo "(exit 1: changes found, as expected)"

echo
echo "== an attacker editing the baseline is caught by the signature =="
python3 - <<'PY'
import json
p = "sandbox/www.fim.json"
doc = json.load(open(p))
first = next(iter(doc["baseline"]["files"]))
doc["baseline"]["files"][first]["sha256"] = "0" * 64
json.dump(doc, open(p, "w"))
PY
fim check -b sandbox/www.fim.json || echo "(exit 3: baseline signature check failed, as expected)"
echo
echo "Demo files are in $(pwd)/sandbox — delete it when you are done."
