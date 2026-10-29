"""Tests for the path canonicalizer (Day 9)."""
import unicodedata

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agentfence.canon.errors import CanonicalizationError, block_for
from agentfence.canon.paths import MAX_COMPONENTS, MAX_LINK_HOPS, canonicalize_path
from agentfence.models import Effect, ReasonCode

ROOTS = ["/workspace"]
LINKS = {
    "/workspace/public/latest": "/workspace/public/readme.txt",
    "/workspace/public/up": "../notes",
    "/workspace/public/shortcut": "/workspace/keys/api_keys.txt",
    "/workspace/public/escape": "/etc",
    "/workspace/public/dir": "/workspace/notes/sub",
    "/workspace/loop/a": "/workspace/loop/b",
    "/workspace/loop/b": "/workspace/loop/a",
    "/workspace/loop/self": "/workspace/loop/self",
}


def canon(raw: object, **kwargs: object) -> str:
    return canonicalize_path(raw, allowed_roots=ROOTS, symlinks=LINKS, **kwargs)  # type: ignore[arg-type]


def denied(raw: object, **kwargs: object) -> None:
    with pytest.raises(CanonicalizationError):
        canon(raw, **kwargs)


# ---------- normal paths and cleanup ----------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/workspace/public/readme.txt", "/workspace/public/readme.txt"),
        ("/workspace//public///readme.txt", "/workspace/public/readme.txt"),
        ("/workspace/./public/./readme.txt", "/workspace/public/readme.txt"),
        ("/workspace/public/../notes/meeting.txt", "/workspace/notes/meeting.txt"),
        ("/workspace/public/", "/workspace/public"),
        ("/workspace", "/workspace"),
        ("public/readme.txt", "/workspace/public/readme.txt"),
        ("./public/readme.txt", "/workspace/public/readme.txt"),
        ("../workspace/public", "/workspace/public"),
        ("/workspace/%2e%2e/etc", "/workspace/%2e%2e/etc"),
    ],
)
def test_clean_paths(raw: str, expected: str) -> None:
    assert canon(raw) == expected


def test_percent_encoding_is_not_decoded_here() -> None:
    assert canon("/workspace/%2e%2e/etc") == "/workspace/%2e%2e/etc"


def test_relative_paths_use_the_given_base() -> None:
    assert canon("readme.txt", base="/workspace/public") == "/workspace/public/readme.txt"


# ---------- outside the allowed roots ----------

@pytest.mark.parametrize(
    "raw",
    [
        "/etc/passwd",
        "/",
        "/workspace-evil/x",
        "/workspac",
        "/WORKSPACE/public/readme.txt",
        "/Workspace",
        "/workspace/../etc/passwd",
        "../x",
        "..",
    ],
)
def test_outside_the_allowed_roots_is_denied(raw: str) -> None:
    denied(raw)


@pytest.mark.parametrize(
    "raw",
    ["/workspace/../../etc", "../../../etc/passwd", "/..", "/../workspace/public"],
)
def test_climbing_above_the_top_is_denied(raw: str) -> None:
    denied(raw)


def test_no_allowed_roots_means_everything_is_denied() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_path("/workspace/public", allowed_roots=[])


def test_several_roots() -> None:
    roots = ["/workspace/public", "/data"]
    assert canonicalize_path("/data/x.csv", allowed_roots=roots) == "/data/x.csv"
    with pytest.raises(CanonicalizationError):
        canonicalize_path("/workspace/notes/meeting.txt", allowed_roots=roots)


@pytest.mark.parametrize("root", ["workspace", "/workspace/", "/a/../b", "/", "/a//b", ""])
def test_bad_roots_are_a_configuration_error(root: str) -> None:
    with pytest.raises(ValueError, match="allowed root"):
        canonicalize_path("/workspace", allowed_roots=[root])


# ---------- bad input ----------

@pytest.mark.parametrize("raw", [5, None, b"/workspace", ["/workspace"], 1.5, True])
def test_non_text_is_denied(raw: object) -> None:
    denied(raw)


@pytest.mark.parametrize("raw", ["", "   ", "\t"])
def test_empty_paths_are_denied(raw: str) -> None:
    denied(raw)


def test_long_and_deep_paths_are_denied() -> None:
    denied("/workspace/" + "a" * 600)
    denied("/workspace/" + "/".join(["d"] * (MAX_COMPONENTS + 1)))
    denied("/workspace/" + "a" * 300)


@pytest.mark.parametrize(
    "raw",
    [
        "/workspace/a\x00.txt",
        "/workspace/a\n/b",
        "/workspace/a\tb",
        "/workspace/a\x00.txt/../../etc",
        "/workspace/a\x7fb",
        "/workspace/\ud800",
    ],
)
def test_control_characters_are_denied(raw: str) -> None:
    denied(raw)


@pytest.mark.parametrize(
    "raw",
    ["\\workspace\\public", "/workspace\\..\\etc", "/workspace/a\\b", "C:\\Windows"],
)
def test_backslashes_are_denied(raw: str) -> None:
    denied(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "/workspace/public/\u202eexe.txt",
        "/workspace/pub\u200blic",
        "/workspace/\ufeffpublic",
        "/workspace/a\u00a0b",
        "/workspace/a\u2003b",
        "/workspace/a\u2028b",
    ],
)
def test_invisible_and_odd_space_characters_are_denied(raw: str) -> None:
    denied(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "\uff0fworkspace\uff0fpublic",
        "/workspace/\uff0e\uff0e/etc",
        "/workspace/\ufb01le.txt",
        "/workspace/\u2460.txt",
    ],
)
def test_lookalike_unicode_forms_are_denied(raw: str) -> None:
    denied(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "//server/share/file",
        "~/secrets",
        "~root/x",
        "C:/Windows/system32",
        "c:foo",
        "/workspace/file.txt::$DATA",
        "/workspace/a:b",
        "/workspace/file.txt.",
        "/workspace/file ",
        "/workspace/...",
    ],
)
def test_ambiguous_platform_forms_are_denied(raw: str) -> None:
    denied(raw)


# ---------- unicode and case ----------

def test_unicode_forms_become_one_canonical_form() -> None:
    composed = "/workspace/public/caf\u00e9.txt"
    decomposed = "/workspace/public/cafe\u0301.txt"
    assert canon(composed) == canon(decomposed)
    assert canon(decomposed) == unicodedata.normalize("NFC", decomposed)


def test_non_english_file_names_are_allowed() -> None:
    raw = "/workspace/public/\u0930\u093f\u092a\u094b\u0930\u094d\u091f.txt"
    assert canon(raw) == unicodedata.normalize("NFC", raw)


def test_case_matters_by_default() -> None:
    assert canon("/workspace/Public/Readme.TXT") == "/workspace/Public/Readme.TXT"
    assert canon("/workspace/Public") != canon("/workspace/public")


def test_fold_case_mode_makes_case_tricks_equal() -> None:
    assert canon("/WORKSPACE/Public/README.TXT", fold_case=True) == "/workspace/public/readme.txt"
    assert canon("/workspace/KEYS/x", fold_case=True) == canon("/workspace/keys/X", fold_case=True)


def test_fold_case_mode_applies_to_symlink_names() -> None:
    assert canon("/Workspace/Public/LATEST", fold_case=True) == "/workspace/public/readme.txt"


# ---------- symlinks ----------

def test_symlink_inside_the_roots_is_resolved() -> None:
    assert canon("/workspace/public/latest") == "/workspace/public/readme.txt"


def test_relative_symlink_target_starts_at_the_links_folder() -> None:
    assert canon("/workspace/public/up/meeting.txt") == "/workspace/notes/meeting.txt"


def test_policy_sees_the_real_target_not_the_link_name() -> None:
    assert canon("/workspace/public/shortcut") == "/workspace/keys/api_keys.txt"


def test_symlink_that_escapes_the_roots_is_denied() -> None:
    denied("/workspace/public/escape")
    denied("/workspace/public/escape/passwd")


def test_dotdot_after_a_symlink_uses_the_real_location() -> None:
    assert canon("/workspace/public/dir/../meeting.txt") == "/workspace/notes/meeting.txt"


@pytest.mark.parametrize(
    "raw", ["/workspace/loop/a", "/workspace/loop/b", "/workspace/loop/self"]
)
def test_symlink_loops_are_denied(raw: str) -> None:
    denied(raw)


def test_long_symlink_chains_are_denied() -> None:
    links = {f"/workspace/c/l{i}": f"/workspace/c/l{i + 1}" for i in range(MAX_LINK_HOPS + 2)}
    links[f"/workspace/c/l{MAX_LINK_HOPS + 2}"] = "/workspace/public/readme.txt"
    with pytest.raises(CanonicalizationError, match="too many"):
        canonicalize_path("/workspace/c/l0", allowed_roots=ROOTS, symlinks=links)


def test_a_chain_within_the_limit_is_allowed() -> None:
    links = {f"/workspace/c/l{i}": f"/workspace/c/l{i + 1}" for i in range(3)}
    links["/workspace/c/l3"] = "/workspace/public/readme.txt"
    result = canonicalize_path("/workspace/c/l0", allowed_roots=ROOTS, symlinks=links)
    assert result == "/workspace/public/readme.txt"


# ---------- decision helper ----------

def test_block_for_builds_a_canonicalization_decision() -> None:
    try:
        canon("/etc/passwd")
    except CanonicalizationError as exc:
        decision = block_for("c1", "path", exc)
    assert decision.effect is Effect.BLOCK
    assert decision.reason_codes == [ReasonCode.CANONICALIZATION_FAILED]
    assert "path" in decision.main_reason
    assert "/etc/passwd" not in decision.main_reason


# ---------- properties (many random inputs) ----------

PIECES = ["", ".", "..", "workspace", "public", "notes", "readme.txt", "latest", "up", "dir", "%2e"]
path_like = st.lists(st.sampled_from(PIECES), max_size=10).map("/".join)
any_path = st.one_of(path_like, path_like.map(lambda p: "/" + p), st.text(max_size=60))


def inside_root(path: str) -> bool:
    return path == "/workspace" or path.startswith("/workspace/")


@settings(max_examples=300, deadline=None)
@given(any_path)
def test_property_result_is_clean_and_inside_the_root(raw: str) -> None:
    try:
        result = canon(raw)
    except CanonicalizationError:
        return
    assert inside_root(result)
    assert ".." not in result.split("/")
    assert "." not in result.split("/")
    assert "//" not in result


@settings(max_examples=300, deadline=None)
@given(any_path)
def test_property_canonicalization_is_idempotent(raw: str) -> None:
    try:
        once = canon(raw)
    except CanonicalizationError:
        return
    assert canon(once) == once


@settings(max_examples=200, deadline=None)
@given(any_path)
def test_property_nothing_escapes_when_roots_are_narrower(raw: str) -> None:
    roots = ["/workspace/public"]
    try:
        result = canonicalize_path(raw, allowed_roots=roots, symlinks=LINKS)
    except CanonicalizationError:
        return
    assert result == "/workspace/public" or result.startswith("/workspace/public/")