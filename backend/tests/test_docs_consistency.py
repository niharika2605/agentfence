"""Keeps docs/invariants.md and the invariant tests in sync."""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = REPO_ROOT / "docs"
SPEC_TEST_FILE = Path(__file__).resolve().parent / "test_invariants_spec.py"


def _test_names_in_doc() -> set[str]:
    text = (DOCS / "invariants.md").read_text(encoding="utf-8")
    return set(re.findall(r"test_i\d_\w+", text))


def test_docs_exist() -> None:
    assert (DOCS / "threat_model.md").is_file()
    assert (DOCS / "invariants.md").is_file()


def test_invariants_doc_lists_seven_tests() -> None:
    assert len(_test_names_in_doc()) == 7


def test_every_documented_invariant_has_a_test() -> None:
    spec_source = SPEC_TEST_FILE.read_text(encoding="utf-8")
    for name in _test_names_in_doc():
        assert f"def {name}(" in spec_source, f"missing test: {name}"