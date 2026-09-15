from __future__ import annotations

import sys
import types
from pathlib import Path

CAPABILITY = Path(__file__).parent.parent / "capabilities" / "rw-checks"
sys.path.insert(0, str(CAPABILITY))
sys.path.insert(0, str(Path(__file__).parent))

from _fakes import RecordingContext  # noqa: E402
from tools._plan import Applicability, Invocation  # noqa: E402

from tools import _runner  # noqa: E402


def test_batches_split_on_count_and_bytes(monkeypatch):
    monkeypatch.setattr(_runner, "MAX_BATCH_FILES", 2)
    assert _runner.batches(["a", "b", "c"]) == [("a", "b"), ("c",)]
    monkeypatch.setattr(_runner, "MAX_BATCH_FILES", 200)
    monkeypatch.setattr(_runner, "MAX_BATCH_ARGV_BYTES", 5)
    assert _runner.batches(["aa", "bb", "cc"]) == [("aa", "bb"), ("cc",)]


def test_files_and_config_are_relative_to_cwd():
    inv = Invocation(files=("svc/a/x.py", "svc/y.py"), config="svc/.pylintrc", cwd="svc")
    assert _runner.files_arg(inv) == ["a/x.py", "y.py"]
    assert _runner.config_arg(inv) == ".pylintrc"
    root = Invocation(files=("x.py",), config=None, cwd="")
    assert _runner.files_arg(root) == ["x.py"] and _runner.config_arg(root) is None


def test_tool_env_points_home_cache_tmp_at_workdir(tmp_path):
    ctx = RecordingContext(tmp_path)
    env = _runner.tool_env(ctx)
    for key in ("HOME", "XDG_CACHE_HOME", "TMPDIR"):
        assert Path(env[key]).is_dir() and Path(env[key]).is_relative_to(ctx.workdir)


def test_tool_env_is_a_complete_allow_list(tmp_path):
    """final-fix-5 G7: tool_env is the WHOLE child env (ctx.run(inherit_env=False)),
    not a few extra vars merged over the pod's own environment -- so every key
    a tool needs to run at all must be set explicitly here."""
    ctx = RecordingContext(tmp_path)
    env = _runner.tool_env(ctx)
    for key in ("PATH", "HOME", "XDG_CACHE_HOME", "TMPDIR", "LANG"):
        assert key in env
    assert env["LANG"] == "C.UTF-8"


def test_tool_env_passes_a_set_proxy_variable_through(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("no_proxy", "localhost")
    ctx = RecordingContext(tmp_path)
    env = _runner.tool_env(ctx)
    assert env["HTTPS_PROXY"] == "http://proxy.example:3128"
    assert env["no_proxy"] == "localhost"


def test_tool_env_excludes_a_secret_looking_variable(tmp_path, monkeypatch):
    """The probe's payload read GPG_KEY out of the pod's own env -- tool_env
    must not carry it, or anything else that isn't on the allow-list."""
    monkeypatch.setenv("GPG_KEY", "totally-secret")
    ctx = RecordingContext(tmp_path)
    env = _runner.tool_env(ctx)
    assert "GPG_KEY" not in env


def test_records_are_remapped_to_repo_relative(tmp_path):
    tree = tmp_path / "tree"
    (tree / "svc").mkdir(parents=True)
    (tree / "svc" / "x.py").write_text("x\n")
    ctx = RecordingContext(tmp_path)
    inv = Invocation(files=("svc/x.py",), config="svc/.pylintrc", cwd="svc")
    got = _runner.records_to_findings(
        ctx,
        tree,
        inv,
        [{"path": "x.py", "rule": "C0114", "line": 1, "severity": "note", "message": "m"}],
    )
    assert [f.path for f in got] == ["svc/x.py"]


def test_realign_paths_maps_a_unique_basename(tmp_path):
    from runwhen_capability.models import Finding

    inv = Invocation(files=(".github/workflows/ci.yml",))
    f = Finding(
        capability="rw-checks", operation="zizmor", rule="r", path="ci.yml", severity="error"
    )
    assert [x.path for x in _runner.realign_paths([f], inv)] == [".github/workflows/ci.yml"]


def test_scratch_view_holds_only_invocation_files(tmp_path):
    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "x.txt").write_text("secret")
    (tree / "other.txt").write_text("not mine")
    (tree / ".gitleaks.toml").write_text("")
    ctx = RecordingContext(tmp_path)
    view = _runner.scratch_view(
        ctx, tree, Invocation(files=("a/x.txt",), config=".gitleaks.toml"), "gitleaks"
    )
    got = sorted(p.relative_to(view).as_posix() for p in view.rglob("*") if p.is_file())
    assert got == [".gitleaks.toml", "a/x.txt"]


def test_endpoint_reachable_caches_per_context(tmp_path, monkeypatch):
    ctx = RecordingContext(tmp_path)
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        raise OSError("down")

    monkeypatch.setattr(_runner.urllib.request, "urlopen", fake_urlopen)
    assert _runner.endpoint_reachable(ctx, "https://api.osv.dev/") is False
    assert _runner.endpoint_reachable(ctx, "https://api.osv.dev/") is False
    assert calls == ["https://api.osv.dev/"]


def test_run_check_batches_filters_and_reports(tmp_path, monkeypatch):
    from runwhen_capability.models import Finding

    monkeypatch.setattr(_runner, "MAX_BATCH_FILES", 1)
    tree = tmp_path / "tree"
    tree.mkdir()
    seen = []

    def mk(p):
        return Finding(capability="rw-checks", operation="t", rule="r", path=p, severity="warning")

    def check(ctx, tree_, inv):
        seen.append(inv.files)
        return [mk(inv.files[0]), mk("not/in/invocation.py")]

    module = types.SimpleNamespace(
        NAME="demo",
        applicable=lambda ctx, t, c: Applicability(
            invocations=(Invocation(files=("a.py", "b.py")),),
            skipped="1 of 3 changed Python files have no demo config",
        ),
        check=check,
    )
    result = _runner.run_check(RecordingContext(tmp_path), tree, ["a.py", "b.py", "c.py"], module)
    assert seen == [("a.py",), ("b.py",)]
    assert [f.path for f in result.findings] == ["a.py", "b.py"]
    assert result.files_checked == 2
    assert result.skipped == "1 of 3 changed Python files have no demo config"


def test_run_check_not_applicable_returns_refusals_and_reason(tmp_path):
    module = types.SimpleNamespace(
        NAME="demo",
        applicable=lambda ctx, t, c: Applicability(skipped="no changed Python files"),
        check=lambda *a: (_ for _ in ()).throw(AssertionError("check must not run")),
    )
    result = _runner.run_check(RecordingContext(tmp_path), tmp_path, [], module)
    assert (
        result.findings == []
        and result.files_checked == 0
        and result.skipped == "no changed Python files"
    )
