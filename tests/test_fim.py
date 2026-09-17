import json
import os

import pytest

from fim import build_baseline, compare, load_baseline, save_baseline
from fim.cli import main
from fim.core import BaselineError, scan


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "site"
    (root / "conf").mkdir(parents=True)
    (root / "index.html").write_text("<h1>hi</h1>")
    (root / "conf" / "app.ini").write_text("debug=false\n")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref")
    return root


def kinds(changes):
    return {(c.kind, c.path) for c in changes}


def test_no_changes(tree):
    base = build_baseline(tree, [".git"])
    assert compare(base, scan(tree, [".git"])) == []
    assert ".git/HEAD" not in base.files


def test_detects_add_remove_modify_and_permissions(tree):
    base = build_baseline(tree, [".git"])
    (tree / "index.html").write_text("<h1>defaced</h1>")
    (tree / "conf" / "app.ini").unlink()
    (tree / "shell.php").write_text("<?php ?>")
    os.chmod(tree / "shell.php", 0o644)
    changes = compare(base, scan(tree, [".git"]))
    assert kinds(changes) == {
        ("modified", "index.html"), ("removed", "conf/app.ini"), ("added", "shell.php")
    }


def test_permission_change(tree):
    os.chmod(tree / "index.html", 0o644)
    base = build_baseline(tree)
    os.chmod(tree / "index.html", 0o777)
    assert kinds(compare(base, scan(tree))) >= {("permissions", "index.html")}


def test_signed_baseline_roundtrip_and_tamper(tree, tmp_path):
    path = tmp_path / "b.json"
    save_baseline(build_baseline(tree), path, key=b"k1")
    assert len(load_baseline(path, key=b"k1").files) == 3
    with pytest.raises(BaselineError, match="signature"):
        load_baseline(path, key=b"wrong")
    doc = json.loads(path.read_text())
    doc["baseline"]["files"]["index.html"]["sha256"] = "0" * 64
    path.write_text(json.dumps(doc))
    with pytest.raises(BaselineError, match="signature"):
        load_baseline(path, key=b"k1")


def test_bad_inputs(tmp_path):
    with pytest.raises(BaselineError):
        build_baseline(tmp_path / "missing")
    (tmp_path / "junk.json").write_text("{not json")
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "junk.json")


def test_symlink_is_recorded_not_followed(tree):
    (tree / "link").symlink_to("/etc/passwd")
    base = build_baseline(tree)
    assert "link" in base.files
    (tree / "link").unlink()
    (tree / "link").symlink_to("/etc/hosts")
    assert kinds(compare(base, scan(tree))) == {("modified", "link")}


def test_cli_init_and_check(tree, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("FIM_KEY", "secret")
    b = str(tmp_path / "base.json")
    assert main(["init", str(tree), "-o", b]) == 0
    assert main(["check", "-b", b]) == 0
    (tree / "index.html").write_text("changed")
    capsys.readouterr()
    assert main(["check", "-b", b, "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out == [{"kind": "modified", "path": "index.html", "detail": "size 11 → 7"}]
    monkeypatch.setenv("FIM_KEY", "other")
    assert main(["check", "-b", b]) == 3
