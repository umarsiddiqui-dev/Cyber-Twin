"""
Context Indexer – CyberTwin Phase 7
Reads all relevant project files and bundles them into a single string
that can be injected into Gemma 4's 128K context window.

Design goals:
  - Walk the backend source tree at call-time (files are small, fast I/O)
  - Include: .py, .md, .txt, .json source/data files
  - Exclude: venv/, __pycache__/, node_modules/, large binary/model files
  - Hard-cap the bundled text at MAX_CHARS to stay well inside 128K tokens
    (1 token ≈ 4 chars → 110K tokens ≈ 440K chars; we use 400K to be safe)
"""

import os
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

# Root of the backend source tree
_BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent   # .../cybertwin-backend

# File extensions to include
_INCLUDE_EXTS = {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".ps1", ".sh"}

# Directory names to skip entirely
_SKIP_DIRS = {
    "venv", ".venv", "__pycache__", ".git", ".pytest_cache",
    "node_modules", "dist", "build", ".idea", ".vscode",
    "htmlcov",
}

# Individual file patterns to skip (by suffix or name)
_SKIP_SUFFIXES = {".pkl", ".npy", ".pyc", ".pyo", ".db", ".sqlite3"}
_SKIP_NAMES    = {"cybertwin.db"}

# Maximum bundled text length (chars) – approx 400K chars ≈ 100K tokens
MAX_CHARS = 400_000

# Maximum bytes per single file to include (skip enormous JSON indexes)
MAX_FILE_BYTES = 80_000   # ~80 KB per file


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.startswith(".")


def _should_skip_file(path: Path) -> bool:
    if path.suffix.lower() in _SKIP_SUFFIXES:
        return True
    if path.name in _SKIP_NAMES:
        return True
    if path.stat().st_size > MAX_FILE_BYTES:
        return True
    return False


def _read_file_safe(path: Path) -> str:
    """Read a text file, returning '' on any encoding error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _walk_tree(root: Path) -> list[Path]:
    """
    Recursively collect readable files under root, respecting skip rules.
    Returns files sorted by path for deterministic ordering.
    """
    results: list[Path] = []
    try:
        for entry in sorted(root.iterdir()):
            if entry.is_dir():
                if not _should_skip_dir(entry.name):
                    results.extend(_walk_tree(entry))
            elif entry.is_file():
                if entry.suffix.lower() in _INCLUDE_EXTS and not _should_skip_file(entry):
                    results.append(entry)
    except PermissionError:
        pass
    return results


_cached_context: str | None = None


def get_project_context(bypass_cache: bool = False) -> str:
    """
    Build and return the full project context string.
    Uses in-memory caching unless bypass_cache is True.

    Each file is wrapped in a header so Gemma can refer to it by name.
    The total output is capped at MAX_CHARS.
    """
    global _cached_context
    if _cached_context is not None and not bypass_cache:
        return _cached_context

    files = _walk_tree(_BACKEND_ROOT)
    chunks: list[str] = []
    total_chars = 0

    for path in files:
        content = _read_file_safe(path)
        if not content.strip():
            continue

        try:
            rel = path.relative_to(_BACKEND_ROOT)
        except ValueError:
            rel = path

        header  = f"\n\n===== FILE: {rel} =====\n"
        snippet = content[:MAX_FILE_BYTES]   # extra safety – already filtered above
        block   = header + snippet

        if total_chars + len(block) > MAX_CHARS:
            # Partial include: take what fits
            remaining = MAX_CHARS - total_chars
            if remaining > len(header) + 200:
                chunks.append(block[:remaining] + "\n[...TRUNCATED...]")
            break

        chunks.append(block)
        total_chars += len(block)

    _cached_context = "".join(chunks)
    logger.info(
        f"[ContextIndexer] Indexed {len(files)} files → "
        f"{total_chars:,} chars bundled for LLM context"
    )
    return _cached_context


def get_project_summary() -> dict:
    """
    Return a lightweight stats dict (file count, total chars) without the full text.
    Useful for health endpoints.
    """
    files = _walk_tree(_BACKEND_ROOT)
    total_bytes = sum(f.stat().st_size for f in files)
    return {
        "files_indexed": len(files),
        "total_source_bytes": total_bytes,
        "max_context_chars": MAX_CHARS,
    }
