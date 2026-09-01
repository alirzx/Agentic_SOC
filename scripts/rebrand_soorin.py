"""One-shot public-identity rebrand: upstream AiSOC URLs -> Soorin GitHub.

Does not rename AISOC_* env vars, Docker service names, or Python imports.
Skips historical subtree plans/cyble-aisoc and generated caches.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    ".next",
    "cyble-aisoc",
    ".turbo",
    "coverage",
    ".venv",
    "venv",
}
TEXT_EXT = {
    ".md",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".yml",
    ".yaml",
    ".sh",
    ".ps1",
    ".json",
    ".toml",
    ".html",
    ".css",
    ".txt",
    ".mdx",
    ".svg",
}
SELF = Path(__file__).resolve()

REPLACEMENTS = (
    ("https://github.com/beenuar/AiSOC", "https://github.com/SoorinSecurity/Agentic_SOC"),
    (
        "https://raw.githubusercontent.com/beenuar/AiSOC",
        "https://raw.githubusercontent.com/SoorinSecurity/Agentic_SOC",
    ),
    ("https://beenuar.github.io/AiSOC", "https://github.com/SoorinSecurity/Agentic_SOC"),
    ("mailto:hello@tryaisoc.com", "mailto:info@soorinsec.ir"),
)


def iter_files() -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.resolve() == SELF:
                continue
            if path.suffix.lower() not in TEXT_EXT:
                continue
            out.append(path)
    return out


def main() -> None:
    changed = 0
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        new = text
        for old, repl in REPLACEMENTS:
            new = new.replace(old, repl)
        if new != text:
            path.write_text(new, encoding="utf-8", newline="\n")
            changed += 1
            print(path.relative_to(ROOT).as_posix())
    print(f"updated {changed} files")


if __name__ == "__main__":
    main()
