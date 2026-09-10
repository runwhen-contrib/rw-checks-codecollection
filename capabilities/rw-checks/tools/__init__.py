"""One module per static-check tool.

A real package, not a directory on sys.path, so a tool is referenced as
`tools.gitleaks` and never collides with the task function of the same name in
tasks.py. It also means each tool is imported under exactly one module name --
importing the same file as both `pylint` and `tools.pylint` would create two
module objects, and patching one would silently not affect the other.

Each module declares SEVERITY, FILES, CONFIG, CI_BINARY and GUARD, and defines
detect() and check(). See _common.py for the contract.
"""
