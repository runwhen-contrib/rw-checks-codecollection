"""One module per static-check tool.

A real package, not a directory on sys.path, so a tool is referenced as
`tools.gitleaks` and never collides with the task function of the same name in
tasks.py. It also means each tool is imported under exactly one module name --
importing the same file as both `pylint` and `tools.pylint` would create two
module objects, and patching one would silently not affect the other.

Each module declares SEVERITY, NAME, KIND, FILES, CONFIG, CONFIG_NAMES,
CI_BINARY, LANE and EXPECT_EXIT, and defines `applicable(ctx, tree, changed)`
and `check(ctx, tree, inv)`. See _plan.py (applicability, config discovery,
invocation planning) and _runner.py (running a planned invocation and turning
its output into findings) for the contract.
"""
