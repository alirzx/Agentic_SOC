"""Verify the production configuration entry point only asks Docker to resolve input."""

import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_config_adds_tkg_overlays_before_private_runtime_override(tmp_path):
    config = tmp_path / "runtime.yaml"
    config.write_text("services: {}\n")
    env_file = tmp_path / "fixture.env"
    env_file.write_text("FIXTURE=1\n")
    capture = tmp_path / "docker-args.json"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "with open(os.environ['FIXTURE_CAPTURE'], 'w') as f:\n"
        "    json.dump(sys.argv[1:], f)\n"
        "print('{}')\n"
    )
    docker.chmod(0o755)
    result = subprocess.run(
        ["bash", "scripts/server55_soc_build.sh", "config"], cwd=ROOT, timeout=10,
        capture_output=True, text=True, env={
            **os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "SOC_COMPOSE_ENV": str(env_file),
            "SOC_RUNTIME_OVERRIDE": str(config), "SOC_TKG_OVERLAY": "private-ca", "FIXTURE_CAPTURE": str(capture),
        },
    )
    # Intentionally incomplete Docker fixture must fail validation without additional Docker calls.
    assert result.returncode != 0
    args = json.loads(capture.read_text())
    assert args[-3:] == ["config", "--format", "json"]
    assert args[args.index("-p") + 1] == "aisoc-demo"
    assert args[args.index("--profile") + 1] == "tkg-sync"
    assert args.index("infra/compose/privacy-ca.override.yml") < args.index("infra/compose/tkg-network.override.yml")
    assert args.index("infra/compose/tkg-ca.override.yml") < args.index(str(config))


def test_static_production_matrix(tmp_path):
    checkout = os.getenv("SOORIN_TKG_CHECKOUT")
    if not checkout:
        pytest.skip("requires an adjacent TKG checkout and Docker Compose config")
    env_file = tmp_path / "fixture.env"
    env_file.write_text("SYNTHETIC_FIXTURE=1\n")
    runtime = tmp_path / "runtime.yml"
    dlp = "\n".join(f"      {key}: '{value}'" for key, value in {
        "AISOC_LLM_PRIVACY_ENABLED": "1", "AISOC_LLM_PRIVACY_REQUIRED": "1", "AISOC_PRIVACY_BACKEND": "remote",
        "AISOC_PRIVACY_REMOTE_URL": "https://privacy-gateway:8443", "AISOC_PRIVACY_REMOTE_API_KEY": "fixture-only",
        "AISOC_AGENTS_TENANT_SIGNING_KEY": "fixture-only-signing-key-000000000000", "ENV": "production",
    }.items())
    runtime.write_text(f"services:\n  api:\n    environment:\n{dlp}\n  agents:\n    environment:\n{dlp}\n")
    exposed = tmp_path / "exposed.yml"
    exposed.write_text(runtime.read_text() + "  ingest-worker:\n    ports: ['0.0.0.0:18888:8080']\n")
    settings = {
        **os.environ, "SOC_COMPOSE_ENV": str(env_file), "SOC_RUNTIME_OVERRIDE": str(runtime),
        "AISOC_BIND_ADDR": "127.0.0.1", "AISOC_PRIVACY_CA_BUNDLE_HOST": str(tmp_path / "fake-dlp-ca"),
        "AISOC_TKG_CA_FILE_HOST": str(tmp_path / "fake-tkg-ca"), "SOORIN_PROD_ENV_FILE": str(env_file),
        "SOORIN_DB_IMAGE": "example.invalid/postgres@sha256:" + "1" * 64,
        "SOORIN_IMAGE": "example.invalid/tkg@sha256:" + "2" * 64,
        "SOORIN_MODEL_IMAGE": "example.invalid/models@sha256:" + "3" * 64,
        "SOORIN_DB_OWNER_PASSWORD": "fixture-only", "SOORIN_DB_RUNTIME_PASSWORD": "fixture-only",
        "SOORIN_RUNTIME_DATABASE_URL": "postgresql://utopia_app:fixture@db/utopia",
        "SOORIN_MIGRATION_DATABASE_URL": "postgresql://utopia:fixture@db/utopia",
        "UTOPIA_JWT_SECRET": "fixture-only", "UTOPIA_SECRET_KEY": "fixture-only",
        "SOORIN_PUBLIC_ORIGIN": "https://fixture.invalid",
    }

    def check(command, cwd, extra, expected):
        result = subprocess.run(command, cwd=cwd, env={**settings, **extra}, capture_output=True, text=True, timeout=10)
        assert (result.returncode == 0) == expected, result.stderr[-1000:]
        assert "fixture-only" not in result.stdout

    soc = ["bash", "scripts/server55_soc_build.sh", "config"]
    tkg = ["bash", "scripts/server55_tkg_production.sh", "config"]
    check(soc, ROOT, {"SOC_TKG_OVERLAY": "off"}, True)
    check(soc, ROOT, {"SOC_TKG_OVERLAY": "on"}, True)
    check(soc, ROOT, {
        "SOC_TKG_OVERLAY": "private-ca", "AISOC_TKG_RECON_PROFILE": "deep_case", "AISOC_TKG_RECON_ENABLED": "true",
        "AISOC_TKG_RECONCILE_ENABLED": "true", "AISOC_TKG_RECONCILE_DATABASE_URL": "postgresql://reconcile:fixture@postgres/aisoc",
    }, True)
    check(soc, ROOT, {"SOC_TKG_OVERLAY": "on", "AISOC_TKG_RECONCILE_ENABLED": "true"}, False)
    check(soc, ROOT, {"SOC_RUNTIME_OVERRIDE": str(exposed)}, False)
    check(tkg, checkout, {"SOORIN_SOC_INTEGRATION": "off"}, True)
    check(tkg, checkout, {"SOORIN_SOC_INTEGRATION": "on"}, True)
    check(tkg, checkout, {"SOORIN_IMAGE": "example.invalid/tkg:latest"}, False)
    check(["python3", "scripts/qualify_tkg_compose.py", "--tkg-checkout", checkout, "--runtime-override", str(runtime),
           "--soc-env", str(env_file), "--tkg-env", str(env_file), "--private-ca"], ROOT, {}, True)
