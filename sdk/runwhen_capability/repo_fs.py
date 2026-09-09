"""ctx.repo_fs -- read-only file/grep/ls access into an already-checked-out
tree, ported from internal/rwcheck/serve/{read,grep,ls}.go in runwhen-runner
(the v1 worktree host), including the glob-depth fix from that repo's
e0c9f16 ("globs match basenames at any depth; empty grep/ls results
marshal as []"). Backs the rw-worktree capability's `read`/`grep`/`ls`
tasks.

Every path input is confined to the tree via pathsafe.safe_path before it
touches disk -- ordinary input validation, not the sandbox mechanism (the
kernel-level sandbox is out of scope; see EXECUTOR-CONTRACT.md's "Open
decisions"). A path that escapes (absolute, "..", or an escaping symlink)
raises PathEscapesTreeError with a clear message. Entries *encountered*
while walking a tree for grep/ls (as opposed to a caller-supplied path) are
handled the same way v1 did: a symlink is skipped/not recursed into rather
than erroring -- it is tree content the walk found, not an input someone
is attempting to escape with.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from .findings import normalize_path
from .models import GrepMatch, GrepResult, LsEntry, LsResult, ReadResult
from .pathsafe import safe_path

# read: CONTRACT.md's caps -- binary detection = NUL byte in the first
# 8 KiB; response content is capped well under the 256 KiB response cap,
# leaving headroom for the rest of the envelope (path, startLine, endLine,
# totalLines, truncated) around content.
BINARY_SNIFF_LEN = 8 * 1024
MAX_READ_RESPONSE_BYTES = 256 * 1024
READ_BUDGET = MAX_READ_RESPONSE_BYTES - 1024

# grep: CONTRACT.md's caps -- "maxMatches?=200 ... <= 200 matches", each
# match's text truncated at 400 chars.
DEFAULT_GREP_MAX_MATCHES = 200
HARD_GREP_MAX_MATCHES = 200
MAX_GREP_MATCH_TEXT_LEN = 400

# ls: CONTRACT.md's cap -- "{entries:[...]} <= 500 entries"; depth 1 is the
# default (immediate children only).
MAX_LS_ENTRIES = 500
DEFAULT_LS_DEPTH = 1


class PathEscapesTreeError(ValueError):
    """A caller-supplied path resolved outside the checked-out tree."""


class BinaryFileError(ValueError):
    """`read` was asked to read a file that sniffs as binary."""


class TreeNotMaterializedError(RuntimeError):
    """`tree` is not a usable checkout -- it does not exist, is not a
    directory, or is an empty directory. Raised by read/grep/ls before any
    of their real work, so an infrastructure failure (a reaped scope, a
    fresh pod, a checkout that never ran) can never be silently reported
    as a genuine zero-match/zero-entry result -- see the module docstring
    for why that distinction matters."""


def _check_tree_materialized(tree: Path) -> None:
    if not tree.exists():
        raise TreeNotMaterializedError(f"tree not materialized: {tree} does not exist")
    if not tree.is_dir():
        raise TreeNotMaterializedError(f"tree not materialized: {tree} is not a directory")
    if not any(tree.iterdir()):
        raise TreeNotMaterializedError(f"tree not materialized: {tree} is empty")


def _confined(tree: Path, path: str) -> Path:
    rel = normalize_path(path or "")
    resolved = safe_path(tree, rel)
    if resolved is None:
        raise PathEscapesTreeError(f"path escapes tree: {path!r}")
    return resolved


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:BINARY_SNIFF_LEN]


# --- read --------------------------------------------------------------


def read_lines(
    tree: Path, path: str, start_line: int | None = None, end_line: int | None = None
) -> ReadResult:
    """Ported from handleRead/selectLines in internal/rwcheck/serve/read.go.
    Reads lines [start_line, end_line] (1-indexed, inclusive; an omitted or
    out-of-range value defaults to the whole file) from `path`, stopping
    early -- and reporting `truncated` -- the instant the joined content
    would push the response past READ_BUDGET."""
    _check_tree_materialized(tree)
    full = _confined(tree, path)
    if not full.is_file():
        raise FileNotFoundError(f"file not found: {path!r}")

    data = full.read_bytes()
    if _is_binary(data):
        raise BinaryFileError(f"binary file: {path!r}")

    lines = data.decode("utf-8", errors="replace").split("\n")
    total_lines = len(lines)

    start = start_line if start_line and start_line >= 1 else 1
    end = end_line if end_line and 0 < end_line <= total_lines else total_lines

    content, truncated, actual_end = _select_lines(lines, start, end)
    return ReadResult(
        path=normalize_path(path),
        content=content,
        startLine=start,
        endLine=actual_end,
        totalLines=total_lines,
        truncated=truncated,
    )


def _select_lines(lines: list[str], start: int, end: int) -> tuple[str, bool, int]:
    if start > end or start > len(lines):
        actual_end = min(start - 1, len(lines))
        return "", False, actual_end

    parts: list[str] = []
    size = 0
    truncated = False
    actual_end = start - 1
    for i in range(start, min(end, len(lines)) + 1):
        line = lines[i - 1]
        add = len(line.encode("utf-8")) + (1 if parts else 0)  # +1: the joining newline
        if size + add > READ_BUDGET and parts:
            truncated = True
            break
        parts.append(line)
        size += add
        actual_end = i
    return "\n".join(parts), truncated, actual_end


# --- grep --------------------------------------------------------------


def _path_match(pattern: str, name: str) -> bool:
    """Go's path.Match semantics: '*'/'?' never cross '/', and the pattern
    and the name must have the same number of '/'-separated segments."""
    pattern_parts = pattern.split("/")
    name_parts = name.split("/")
    if len(pattern_parts) != len(name_parts):
        return False
    return all(fnmatch.fnmatchcase(np, pp) for pp, np in zip(pattern_parts, name_parts))


def match_glob(glob: str, rel: str) -> bool:
    """Ported from matchGlob in internal/rwcheck/serve/grep.go (the
    e0c9f16 fix): a glob with no "/" (e.g. "*.py") matches at ANY depth --
    against rel's basename -- rather than only at the repo root, since a
    bare path.Match-equivalent never crosses "/". A leading "**/" is
    stripped first, so "**/*.py" behaves exactly like "*.py". Any other
    glob (one that still contains "/" after stripping "**/") is matched
    against the full repo-relative path, e.g. "tools/*.py" matches only
    files directly inside tools/, not tools/utils/*.py."""
    g = glob[3:] if glob.startswith("**/") else glob
    if "/" not in g:
        return _path_match(g, os.path.basename(rel))
    return _path_match(g, rel)


def _walk_files(tree: Path):
    """Depth-first, lexically sorted per directory (mirrors
    filepath.WalkDir's default order), skipping ".git" entirely and any
    symlink (file or directory) without following it -- ported from
    grepWorktree's walk in internal/rwcheck/serve/grep.go."""
    tree = Path(tree)
    for root, dirnames, filenames in os.walk(tree, followlinks=False):
        root_path = Path(root)
        dirnames.sort()
        filenames.sort()

        kept_dirs = []
        for d in dirnames:
            full_d = root_path / d
            rel_d = normalize_path(str(full_d.relative_to(tree)))
            if rel_d == ".git" or full_d.is_symlink():
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fn in filenames:
            full = root_path / fn
            if full.is_symlink():
                continue
            rel = normalize_path(str(full.relative_to(tree)))
            if rel == ".git":
                continue
            yield rel, full


def _grep_file(
    full: Path, rel: str, pattern: re.Pattern, limit: int, matches: list[GrepMatch]
) -> bool:
    """Scans one file line by line, appending every match until `limit` is
    reached, returning True the instant that happens so the caller can stop
    walking rather than scan the rest of the tree for matches nobody will
    see. Ported from grepFile in internal/rwcheck/serve/grep.go."""
    try:
        data = full.read_bytes()
    except OSError:
        return False  # an unreadable file must not fail the whole walk
    if _is_binary(data):
        return False  # binary -- skip, not an error

    text = data.decode("utf-8", errors="replace")
    for line_no, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line.rstrip("\r")  # mirrors bufio.ScanLines' CRLF handling
        if not pattern.search(line):
            continue
        line_bytes = line.encode("utf-8")
        if len(line_bytes) > MAX_GREP_MATCH_TEXT_LEN:
            snippet = line_bytes[:MAX_GREP_MATCH_TEXT_LEN].decode("utf-8", errors="ignore")
        else:
            snippet = line
        matches.append(GrepMatch(path=rel, line=line_no, text=snippet))
        if len(matches) >= limit:
            return True
    return False


def grep_tree(
    tree: Path,
    pattern: str,
    glob: str | None = None,
    max_matches: int | None = None,
    ignore_case: bool = False,
) -> GrepResult:
    """Ported from handleGrep/grepWorktree in internal/rwcheck/serve/grep.go.
    `pattern` is a regular expression (Python's `re`, not Go's RE2 -- most
    patterns behave identically, but this is not a byte-for-byte port of
    the regex *engine*, only of the walk/glob/cap behaviour around it)."""
    _check_tree_materialized(Path(tree))
    try:
        compiled = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ValueError(f"invalid pattern: {exc}") from exc

    limit = max_matches if max_matches and max_matches > 0 else DEFAULT_GREP_MAX_MATCHES
    limit = min(limit, HARD_GREP_MAX_MATCHES)

    matches: list[GrepMatch] = []
    for rel, full in _walk_files(tree):
        if glob and not match_glob(glob, rel):
            continue
        if _grep_file(full, rel, compiled, limit, matches):
            break
        if len(matches) >= limit:
            break

    return GrepResult(matches=matches, truncated=len(matches) >= limit)


# --- ls ------------------------------------------------------------------


def _ls_walk(
    directory: Path, rel_prefix: str, depth: int, max_depth: int, entries: list[LsEntry]
) -> None:
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return

    for name in names:
        if len(entries) >= MAX_LS_ENTRIES:
            return

        full = directory / name
        rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
        if rel_path == ".git":
            continue

        if full.is_symlink():
            typ, size = "other", 0
        elif full.is_dir():
            typ, size = "dir", 0
        else:
            typ = "file"
            try:
                size = full.stat().st_size
            except OSError:
                size = 0
        entries.append(LsEntry(path=rel_path, type=typ, size=size))

        if typ == "dir" and depth < max_depth and len(entries) < MAX_LS_ENTRIES:
            _ls_walk(full, rel_path, depth + 1, max_depth, entries)


def ls_tree(tree: Path, path: str | None = None, depth: int | None = None) -> LsResult:
    """Ported from handleLs/lsWalk in internal/rwcheck/serve/ls.go. Lists
    `path` (repo root when omitted) up to `depth` levels deep (default 1:
    immediate children only), sorted lexically per directory, skipping
    ".git" entirely and capping the total at MAX_LS_ENTRIES."""
    _check_tree_materialized(Path(tree))
    root = _confined(tree, path or "")
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {path!r}")

    max_depth = depth if depth and depth > 0 else DEFAULT_LS_DEPTH
    entries: list[LsEntry] = []
    _ls_walk(root, "", 1, max_depth, entries)
    return LsResult(entries=entries)


class RepoFsClient:
    """`ctx.repo_fs` -- the rw-worktree capability's read/grep/ls
    operations against an already-checked-out tree (see git.py's
    GitClient.checkout / this capability's `open` setup for how the tree
    itself is materialised)."""

    def __init__(self, ctx) -> None:
        self._ctx = ctx

    def read(
        self, tree: Path, path: str, start_line: int | None = None, end_line: int | None = None
    ) -> ReadResult:
        return read_lines(Path(tree), path, start_line=start_line, end_line=end_line)

    def grep(
        self,
        tree: Path,
        pattern: str,
        glob: str | None = None,
        max_matches: int | None = None,
        ignore_case: bool = False,
    ) -> GrepResult:
        return grep_tree(
            Path(tree), pattern, glob=glob, max_matches=max_matches, ignore_case=ignore_case
        )

    def ls(self, tree: Path, path: str | None = None, depth: int | None = None) -> LsResult:
        return ls_tree(Path(tree), path=path, depth=depth)
