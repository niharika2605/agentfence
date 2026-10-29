"""Path canonicalizer (Day 9).

Turns a raw path from the agent into one canonical absolute path, or raises
CanonicalizationError. Policy then checks the canonical path, never the raw one.

Rules:
- Only text. No control, invisible or look alike characters, no backslashes.
- Unicode is normalized (NFC). Characters that change under NFKC are denied.
- Relative paths are resolved against a base directory.
- '.', '..' and repeated slashes are resolved. Going above '/' is denied.
- Symlinks are resolved first, then '..' applies to the real location.
- The final path must be inside one of the allowed roots (default deny).
- Percent encoding is NOT decoded here. Day 11 decodes values before this runs.
"""
import unicodedata
from collections import deque
from collections.abc import Mapping, Sequence

from agentfence.canon.errors import CanonicalizationError

MAX_PATH_CHARS = 500
MAX_COMPONENTS = 40
MAX_COMPONENT_CHARS = 255
MAX_LINK_HOPS = 8
DEFAULT_BASE = "/workspace"


def _normalize(text: str, *, fold_case: bool) -> str:
    text = unicodedata.normalize("NFC", text)
    if fold_case:
        text = unicodedata.normalize("NFC", text.casefold())
    return text


def _check_characters(text: str) -> None:
    for char in text:
        category = unicodedata.category(char)
        if char == "\\":
            raise CanonicalizationError("backslashes are not allowed")
        if category[0] == "C" or category in ("Zl", "Zp"):
            raise CanonicalizationError("control or invisible characters are not allowed")
        if category == "Zs" and char != " ":
            raise CanonicalizationError("unusual space characters are not allowed")
    nfc = unicodedata.normalize("NFC", text)
    if unicodedata.normalize("NFKC", nfc) != nfc:
        raise CanonicalizationError("look alike unicode forms are not allowed")


def _check_component(part: str) -> None:
    if len(part) > MAX_COMPONENT_CHARS:
        raise CanonicalizationError("a path part is too long")
    if ":" in part:
        raise CanonicalizationError("colons are not allowed in a path part")
    if part.endswith((".", " ")):
        raise CanonicalizationError("a path part may not end with a dot or space")


def _check_root(root: str) -> None:
    parts = root.split("/")[1:]
    valid = (
        root.startswith("/")
        and root != "/"
        and not root.endswith("/")
        and all(p not in ("", ".", "..") for p in parts)
    )
    if not valid:
        raise ValueError(f"allowed root must be a clean absolute path: {root!r}")


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def canonicalize_path(
    raw: object,
    *,
    allowed_roots: Sequence[str],
    symlinks: Mapping[str, str] | None = None,
    base: str = DEFAULT_BASE,
    fold_case: bool = False,
) -> str:
    """Return the canonical absolute path, or raise CanonicalizationError."""
    if not isinstance(raw, str):
        raise CanonicalizationError("path must be text")
    if not raw.strip():
        raise CanonicalizationError("path is empty")
    if len(raw) > MAX_PATH_CHARS:
        raise CanonicalizationError("path is too long")

    roots = list(allowed_roots)
    for root in roots:
        _check_root(root)
    roots = [_normalize(r, fold_case=fold_case) for r in roots]
    links = {
        _normalize(key, fold_case=fold_case): target for key, target in (symlinks or {}).items()
    }

    _check_characters(raw)
    text = _normalize(raw, fold_case=fold_case)

    if text.startswith("//"):
        raise CanonicalizationError("network style paths are not allowed")
    if text.startswith("~"):
        raise CanonicalizationError("home directory shortcuts are not allowed")
    if len(text) >= 2 and text[0].isalpha() and text[1] == ":":
        raise CanonicalizationError("drive letters are not allowed")
    if not text.startswith("/"):
        text = _normalize(base, fold_case=fold_case) + "/" + text

    todo: deque[str] = deque(text.split("/"))
    resolved: list[str] = []
    hops = 0
    steps = 0
    while todo:
        steps += 1
        if steps > MAX_COMPONENTS * (MAX_LINK_HOPS + 1):
            raise CanonicalizationError("path is too complex")
        part = todo.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise CanonicalizationError("path climbs above the top directory")
            resolved.pop()
            continue
        _check_component(part)
        candidate = "/" + "/".join([*resolved, part])
        target = links.get(candidate)
        if target is not None:
            hops += 1
            if hops > MAX_LINK_HOPS:
                raise CanonicalizationError("too many symbolic links")
            target = _normalize(target, fold_case=fold_case)
            if target.startswith("/"):
                resolved = []
            todo.extendleft(reversed(target.split("/")))
            continue
        resolved.append(part)
        if len(resolved) > MAX_COMPONENTS:
            raise CanonicalizationError("path is too deep")

    path = "/" + "/".join(resolved)
    if not any(_inside(path, root) for root in roots):
        raise CanonicalizationError("path is outside the allowed folders")
    return path