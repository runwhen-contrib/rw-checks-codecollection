"""Every task's return shape must match the output kind its manifest declares.

WHY THIS EXISTS
The 22-check expansion rewrote `tasks.py` into thin per-tool registrations and,
in doing so, dropped the `ctx.findings.cap()` call at the task boundary. Every
task then returned a BARE LIST where `rw.findings.v1` is the
`{findings, truncated}` envelope, and papi rejected every result outright:

    task 'ruff' output 'findings': [...] is not of type 'object'

Nothing caught it. The unit suite asserted the bare-list shape (so it passed),
the image smoke test only asserts a task ran without erroring, and the schema is
only enforced on the platform side -- after the result has crossed the wire. It
surfaced on a live pull request, where the whole scan was discarded.

`truncated` is the only way a consumer can tell a capped list from a complete
one, which is why the envelope is the contract and papi refuses a bare array
rather than coercing it. See `models.FindingsResult` and
`findings.FindingsClient.cap`, whose own docstring says to call it last, "so the
cap applies to the exact list the task is about to return" -- i.e. exactly here.

WHY IT IS STATIC
Checking this by *running* each task would need the real tools on PATH, so it
would only work inside the built image and would not run in the unit suite at
all -- which is the gap that let this ship. Reading the manifest and the AST
needs nothing, runs in milliseconds, and fails on the commit that reintroduces
the bug rather than on a customer's pull request.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
import yaml

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Output kind -> the call every task declaring it must wrap its return value in.
#: A kind absent here is not checked; add it with its wrapper when one is added.
_REQUIRED_WRAPPER = {"rw.findings.v1": "ctx.findings.cap"}


def _manifest(capability: str) -> dict:
    return yaml.safe_load((_ROOT / "capabilities" / capability / "manifest.yaml").read_text())


def _task_functions(capability: str) -> dict[str, ast.FunctionDef]:
    tree = ast.parse((_ROOT / "capabilities" / capability / "tasks.py").read_text())
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def _declared_outputs(capability: str) -> list[tuple[str, str, str]]:
    """(task_name, output_name, kind) for every declared output."""
    out = []
    for task in _manifest(capability).get("tasks") or []:
        for name, spec in (task.get("outputs") or {}).items():
            kind = spec.get("kind") if isinstance(spec, dict) else spec
            out.append((task["name"], name, kind))
    return out


def _returned_keys(fn: ast.FunctionDef) -> set[str]:
    keys: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            keys |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    return keys


def _wrapper_call(fn: ast.FunctionDef, output_name: str) -> str | None:
    """The dotted call wrapping `output_name`'s value in `fn`'s return dict."""
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)):
            continue
        for key, value in zip(node.value.keys, node.value.values, strict=False):
            if not (isinstance(key, ast.Constant) and key.value == output_name):
                continue
            if isinstance(value, ast.Call):
                return ast.unparse(value.func)
            return None
    return None


@pytest.mark.parametrize("capability", ["rw-checks", "rw-worktree"])
def test_every_declared_output_is_actually_returned(capability):
    """A task must return a dict carrying every output key its manifest declares."""
    functions = _task_functions(capability)
    for task_name, output_name, _kind in _declared_outputs(capability):
        fn = functions.get(task_name)
        assert fn is not None, (
            f"{capability}: manifest declares task '{task_name}' with no function"
        )
        assert output_name in _returned_keys(fn), (
            f"{capability}: task '{task_name}' declares output "
            f"'{output_name}' but never returns that key"
        )


@pytest.mark.parametrize("capability", ["rw-checks", "rw-worktree"])
def test_findings_outputs_return_the_envelope_not_a_bare_list(capability):
    """`rw.findings.v1` is the {findings, truncated} envelope, so every task
    declaring it must wrap its value in `ctx.findings.cap(...)`.

    Returning the bare list papi rejects is the exact regression this file
    exists to prevent -- it shipped once and discarded a whole live scan.
    """
    functions = _task_functions(capability)
    checked = 0
    for task_name, output_name, kind in _declared_outputs(capability):
        wrapper = _REQUIRED_WRAPPER.get(kind)
        if wrapper is None:
            continue
        actual = _wrapper_call(functions[task_name], output_name)
        assert actual == wrapper, (
            f"{capability}: task '{task_name}' output '{output_name}' is declared {kind}, "
            f"which is an envelope -- expected it wrapped in {wrapper}(...), got "
            f"{actual or 'a bare value'}. papi validates this shape and rejects a bare array."
        )
        checked += 1
    if capability == "rw-checks":
        assert checked == 22, f"expected all 22 rw-checks tasks to be checked, checked {checked}"
