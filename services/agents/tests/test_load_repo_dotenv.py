"""Tests for monorepo .env loader (last-wins duplicate keys)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.load_repo_dotenv import load_repo_dotenv


def test_load_repo_dotenv_last_key_wins(tmp_path: Path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPENAI_API_KEY=first-key\nOPENAI_API_KEY=second-key\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("scripts.load_repo_dotenv._REPO_ROOT", tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    load_repo_dotenv()
    assert os.environ["OPENAI_API_KEY"] == "second-key"
