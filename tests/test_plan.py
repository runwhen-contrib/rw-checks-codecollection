from __future__ import annotations

import sys
import types
from pathlib import Path

CAPABILITY = Path(__file__).parent.parent / "capabilities" / "rw-checks"
sys.path.insert(0, str(CAPABILITY))

from runwhen_capability import Context  # noqa: E402
from tools._plan import Applicability, ConfigName, Invocation, Resolved  # noqa: E402

from tools import _plan  # noqa: E402


def _ctx(tmp_path):
    return Context(capability="rw-checks", operation="t", workdir=tmp_path / "work")


def _write(tree: Path, rel: str, text: str = "x\n") -> None:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _module(**overrides):
    base = dict(
        NAME="pylint",
        KIND="Python",
        FILES=("*.py",),
        CONFIG="required",
        CONFIG_NAMES=(ConfigName(".pylintrc"), ConfigName("pyproject.toml", ("tool", "pylint"))),
        CONFIG_SCOPE="nearest",
        CI_BINARY=None,
        GUARD=None,
        GUARD_CHAIN=False,
        LANE="B",
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def test_matches_basename_and_rooted_path_patterns():
    assert _plan.matches("a/b/x.py", ("*.py",))
    assert _plan.matches(".github/workflows/ci.yml", (".github/workflows/*.yml",))
    assert not _plan.matches("sub/.github/workflows/ci.yml", (".github/workflows/*.yml",))
    assert not _plan.matches(".github/workflows/nested/ci.yml", (".github/workflows/*.yml",))
    assert _plan.matches("anything.bin", ())


def test_eligible_files_skips_missing_and_escaping_files(tmp_path):
    tree = tmp_path / "tree"
    _write(tree, "a/x.py")
    (tree / "link.py").symlink_to(tmp_path / "outside.py")
    (tmp_path / "outside.py").write_text("x")
    got = _plan.eligible_files(tree, ["a/x.py", "gone.py", "link.py", "a/readme.md"], ("*.py",))
    assert got == ["a/x.py"]


def test_nearest_config_walks_up_and_honours_sections(tmp_path):
    tree = tmp_path / "tree"
    _write(
        tree, "svc/pyproject.toml", "[tool.poetry]\nname='x'\n"
    )  # no [tool.pylint] -> does not count
    _write(tree, ".pylintrc", "[MAIN]\n")
    _write(tree, "svc/pkg/mod.py")
    names = (ConfigName(".pylintrc"), ConfigName("pyproject.toml", ("tool", "pylint")))
    assert _plan.nearest_config(tree, "svc/pkg/mod.py", names) == Resolved(".pylintrc", "")
    _write(tree, "svc/pyproject.toml", "[tool.pylint.main]\njobs=1\n")
    assert _plan.nearest_config(tree, "svc/pkg/mod.py", names) == Resolved(
        "svc/pyproject.toml", "svc"
    )


def test_nearest_config_dir_bearing_name_and_root_scope(tmp_path):
    tree = tmp_path / "tree"
    _write(tree, "policy/.regal/config.yaml", "rules: {}\n")
    _write(tree, "policy/authz/p.rego")
    assert _plan.nearest_config(
        tree, "policy/authz/p.rego", (ConfigName(".regal/config.yaml"),)
    ) == Resolved("policy/.regal/config.yaml", "policy")
    _write(tree, "sub/.gitleaks.toml", "")
    _write(tree, "sub/a.txt")
    assert (
        _plan.nearest_config(tree, "sub/a.txt", (ConfigName(".gitleaks.toml"),), scope="root")
        is None
    )


def test_plan_no_diff_skips_everything(tmp_path):
    a = _plan.plan(_ctx(tmp_path), tmp_path, None, _module())
    assert a == Applicability(skipped="base commit unavailable; nothing to scope to")


def test_plan_no_matching_files(tmp_path):
    _write(tmp_path, "README.md")
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["README.md"], _module())
    assert a.invocations == () and a.skipped == "no changed Python files"


def test_plan_ci_duplicate_skips_before_config(tmp_path):
    _write(tmp_path, "x.py")
    _write(tmp_path, ".github/workflows/ci.yml", "jobs: {a: {steps: [{run: pylint src}]}}\n")
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["x.py"], _module(CI_BINARY="pylint"))
    assert a.skipped == "pylint already runs in .github/workflows/ci.yml"


def test_plan_required_config_missing(tmp_path):
    _write(tmp_path, "x.py")
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["x.py"], _module())
    assert a.invocations == () and a.skipped == "no pylint config applies to the changed files"


def test_plan_groups_by_config_in_lane_b_and_reports_partial(tmp_path):
    _write(tmp_path, "a/.pylintrc", "[MAIN]\n")
    _write(tmp_path, "b/.pylintrc", "[MAIN]\n")
    for f in ("a/x.py", "a/y.py", "b/z.py", "c/w.py"):
        _write(tmp_path, f)
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["b/z.py", "a/y.py", "a/x.py", "c/w.py"], _module())
    assert a.invocations == (
        Invocation(files=("a/x.py", "a/y.py"), config="a/.pylintrc", cwd="a"),
        Invocation(files=("b/z.py",), config="b/.pylintrc", cwd="b"),
    )
    assert a.skipped == "1 of 4 changed Python files have no pylint config"


def test_plan_lane_a_is_one_root_invocation(tmp_path):
    _write(tmp_path, "a/ruff.toml", "")
    _write(tmp_path, "b/ruff.toml", "")
    _write(tmp_path, "a/x.py")
    _write(tmp_path, "b/y.py")
    mod = _module(NAME="ruff", CONFIG_NAMES=(ConfigName("ruff.toml"),), LANE="A")
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["a/x.py", "b/y.py"], mod)
    assert a.invocations == (Invocation(files=("a/x.py", "b/y.py"), config=None, cwd=""),)


def test_plan_lane_a_passes_a_single_shared_config(tmp_path):
    _write(tmp_path, ".github/actionlint.yaml", "")
    _write(tmp_path, ".github/workflows/ci.yml")
    mod = _module(
        NAME="actionlint",
        KIND="workflow",
        FILES=(".github/workflows/*.yml",),
        CONFIG="optional",
        CONFIG_NAMES=(ConfigName(".github/actionlint.yaml"),),
        CONFIG_SCOPE="root",
        LANE="A",
    )
    a = _plan.plan(_ctx(tmp_path), tmp_path, [".github/workflows/ci.yml"], mod)
    assert a.invocations == (
        Invocation(files=(".github/workflows/ci.yml",), config=".github/actionlint.yaml", cwd=""),
    )


def test_plan_optional_config_keeps_unconfigured_files(tmp_path):
    _write(tmp_path, "Dockerfile")
    mod = _module(
        NAME="hadolint",
        KIND="Dockerfile",
        FILES=("Dockerfile*",),
        CONFIG="optional",
        CONFIG_NAMES=(ConfigName(".hadolint.yaml"),),
    )
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["Dockerfile"], mod)
    assert a.invocations == (Invocation(files=("Dockerfile",), config=None, cwd=""),)
    assert a.skipped is None


def test_plan_guard_refuses_only_its_group(tmp_path):
    _write(tmp_path, "bad/.pylintrc", "[MAIN]\ninit-hook=import os\n")
    _write(tmp_path, "good/.pylintrc", "[MAIN]\n")
    _write(tmp_path, "bad/x.py")
    _write(tmp_path, "good/y.py")

    def guard(tree, paths):
        for p in paths:
            if "init-hook" in p.read_text():
                rel = p.relative_to(tree).as_posix()
                return f"{rel}: sets init-hook, which executes arbitrary Python"
        return None

    a = _plan.plan(_ctx(tmp_path), tmp_path, ["bad/x.py", "good/y.py"], _module(GUARD=guard))
    assert a.invocations == (Invocation(files=("good/y.py",), config="good/.pylintrc", cwd="good"),)
    assert [f.path for f in a.refusals] == ["bad/.pylintrc"]
    assert a.skipped == "1 of 2 changed Python files use an unsafe pylint config (bad/.pylintrc)"


def test_plan_every_group_refused(tmp_path):
    _write(tmp_path, ".pylintrc", "init-hook=x\n")
    _write(tmp_path, "x.py")
    a = _plan.plan(
        _ctx(tmp_path),
        tmp_path,
        ["x.py"],
        _module(GUARD=lambda t, p: ".pylintrc: sets init-hook, bad"),
    )
    assert a.invocations == () and len(a.refusals) == 1
    assert a.skipped == "every applicable pylint config is unsafe"


def test_guard_paths_chain_from_root_to_config(tmp_path):
    _write(tmp_path, ".sqlfluff", "[sqlfluff]\n")
    _write(tmp_path, "db/setup.cfg", "[metadata]\n")  # no [sqlfluff] section -> not in chain
    _write(tmp_path, "db/q/.sqlfluff", "[sqlfluff]\n")
    mod = _module(
        NAME="sqlfluff",
        CONFIG_NAMES=(ConfigName(".sqlfluff"), ConfigName("setup.cfg", ("sqlfluff",))),
        GUARD_CHAIN=True,
    )
    paths = _plan.guard_paths(tmp_path, Resolved("db/q/.sqlfluff", "db/q"), mod)
    assert [p.relative_to(tmp_path).as_posix() for p in paths] == [".sqlfluff", "db/q/.sqlfluff"]


def test_plan_narrow_hook_can_drop_files_with_a_reason(tmp_path):
    _write(tmp_path, ".flake8", "[flake8]\n")
    _write(tmp_path, "x.py")

    def narrow(ctx, tree, changed, groups):
        return {}, "2 changed Python files are covered by ruff"

    mod = _module(NAME="flake8", CONFIG_NAMES=(ConfigName(".flake8"),), narrow=narrow)
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["x.py"], mod)
    assert a.invocations == () and a.skipped == "2 changed Python files are covered by ruff"


def test_plan_group_hook_overrides_lane_grouping(tmp_path):
    _write(tmp_path, "m/.tflint.hcl", "")
    _write(tmp_path, "m/main.tf")
    mod = _module(
        NAME="tflint",
        KIND="Terraform",
        FILES=("*.tf",),
        CONFIG_NAMES=(ConfigName(".tflint.hcl"),),
        LANE="D",
        group=lambda tree, groups: tuple(
            Invocation(files=(f,), config=r.path, cwd="") for r, fs in groups.items() for f in fs
        ),
    )
    a = _plan.plan(_ctx(tmp_path), tmp_path, ["m/main.tf"], mod)
    assert a.invocations == (Invocation(files=("m/main.tf",), config="m/.tflint.hcl", cwd=""),)
