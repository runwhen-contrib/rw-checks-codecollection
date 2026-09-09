"""Golden-vector test: the fingerprint must byte-match
runwhen-runner/internal/rwcheck/fingerprint's Go implementation. The vectors
below are copied verbatim from fingerprint_test.go's goldenVector and its
table -- if these values ever need to change, the Go side changed first and
this is a contract break, not a bug here.
"""

from runwhen_capability.findings import compute, normalize_context, normalize_path

GOLDEN_VECTOR = "a6fd84423d29e6f918a954ed952f8cfd"


def test_golden_vector():
    got = compute("rw-checks", "ruff", "F401", "src/x.py", "import os")
    assert got == GOLDEN_VECTOR
    assert len(got) == 32


def test_tabs_collapse_to_a_single_space():
    got = compute("rw-checks", "ruff", "F401", "src/x.py", "import\tos")
    assert got == GOLDEN_VECTOR


def test_repeated_internal_spaces_collapse():
    got = compute("rw-checks", "ruff", "F401", "src/x.py", "import    os")
    assert got == GOLDEN_VECTOR


def test_crlf_is_stripped_as_trailing_whitespace():
    got = compute("rw-checks", "ruff", "F401", "src/x.py", "import os\r\n")
    assert got == GOLDEN_VECTOR


def test_leading_and_trailing_whitespace_trimmed():
    got = compute("rw-checks", "ruff", "F401", "src/x.py", "  import os  ")
    assert got == GOLDEN_VECTOR


def test_leading_dot_slash_stripped_from_path():
    got = compute("rw-checks", "ruff", "F401", "./src/x.py", "import os")
    assert got == GOLDEN_VECTOR


def test_empty_context():
    got = compute("rw-checks", "ruff", "F401", "src/x.py", "")
    assert got == "285340dd3eeff7fa768ec9e68cd98059"


def test_different_rule_id_changes_the_fingerprint():
    got = compute("rw-checks", "ruff", "E501", "src/x.py", "import os")
    assert got == "8785a16d0a88bf1ae963002554c93240"


def test_normalize_context():
    assert normalize_context("import os") == "import os"
    assert normalize_context("import\tos") == "import os"
    assert normalize_context("import   os") == "import os"
    assert normalize_context("import os\r\nmore\r\n") == "import os more"
    assert normalize_context("   import os   ") == "import os"
    assert normalize_context("") == ""
    assert normalize_context("   \t  ") == ""


def test_normalize_path():
    assert normalize_path("src/x.py") == "src/x.py"
    assert normalize_path("./src/x.py") == "src/x.py"
    assert normalize_path("src\\x.py") == "src/x.py"
    assert normalize_path("x.py") == "x.py"
