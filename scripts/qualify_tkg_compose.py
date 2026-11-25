#!/usr/bin/env python3
"""Resolve both Compose stacks and compare the SOC privacy/runtime configuration."""

import argparse
import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

SOC_OVERRIDES = (
    "infra/compose/docker-compose.demo.yml",
    "infra/compose/privacy-network.override.yml",
    "infra/compose/privacy-ca.override.yml",
)
TKG_OVERRIDES = (
    "docker-compose.production.yml",
    "docker-compose.models-production.yml",
    "docker-compose.tkg-network.override.yml",
)


def resolve(directory, files, env_file, project=None, *, profile="tkg-sync"):
    cmd = ["docker", "compose", "--project-directory", str(directory)]
    if env_file:
        cmd += ["--env-file", str(env_file.resolve())]
    if project:
        cmd += ["-p", project, "--profile", profile]
    for path in files:
        cmd += ["-f", str(directory / path)]
    result = subprocess.run(cmd + ["config", "--format", "json"], capture_output=True, check=False, timeout=30)
    if result.returncode:
        raise SystemExit("Compose resolution failed. Check file paths and required environment values locally.")
    return json.loads(result.stdout)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def validate(before, after, tkg, *, private_ca):
    services = after["services"]
    for name, baseline in before["services"].items():
        current = services[name]
        require(set(baseline.get("networks", ())) <= set(current.get("networks", ())), f"{name}: lost a network")
        require(
            all(current.get("environment", {}).get(k) == v for k, v in baseline.get("environment", {}).items()),
            f"{name}: an existing runtime environment value changed",
        )
        require(all(m in current.get("volumes", []) for m in baseline.get("volumes", [])), f"{name}: an existing mount changed")
        require(current.get("depends_on") == baseline.get("depends_on"), f"{name}: dependency configuration changed")
        require(current.get("command") == baseline.get("command"), f"{name}: service command changed")
    for name in ("api", "agents"):
        require("privacy_gateway" in services[name]["networks"], f"{name}: privacy attachment missing")
        require(
            services[name]["environment"].get("SSL_CERT_FILE") == "/run/secrets/aisoc-dlp-ca.pem",
            f"{name}: DLP TLS trust mount is not configured",
        )
    require(after["networks"]["privacy_gateway"]["name"] == "aisoc-privacy", "Unexpected DLP network name")
    for stack in (after, tkg):
        net = stack["networks"]["aisoc_tkg"]
        require(net.get("external") and net["name"] == "aisoc-tkg", "TKG external network mismatch")
    require(
        {k for k, v in services.items() if "aisoc_tkg" in v.get("networks", {})} == {"api", "agents", "tkg-sync", "tkg-reconcile"},
        "Unexpected SOC service attached to aisoc-tkg",
    )
    require(
        {k for k, v in tkg["services"].items() if "aisoc_tkg" in v.get("networks", {})} == {"app"},
        "Unexpected TKG service attached to aisoc-tkg",
    )
    app = tkg["services"]["app"]
    require(set(tkg["services"]) == {"app", "db", "models"}, "Unexpected hardened TKG model topology")
    models = tkg["services"]["models"]
    require("models" in app["networks"] and set(models["networks"]) == {"models"}, "Unified models are not private")
    require(tkg["networks"]["models"].get("internal"), "TKG model network must be internal")
    require("soorin-tkg" in app["networks"]["aisoc_tkg"]["aliases"], "TKG DNS alias is missing")
    require(app["environment"].get("UTOPIA_BIND_ADDR") == "0.0.0.0:1516", "TKG internal listener mismatch")
    require(all(not v.get("ports") for k, v in tkg["services"].items() if k != "app"), "TKG dependency ports are published")
    require(
        all(port.get("host_ip") in {"127.0.0.1", "::1"} for port in app.get("ports", [])),
        "TKG application publishes a host listener outside loopback",
    )
    # The existing connector ingest route trusts service-network provenance.
    for name in ("ingest-worker", "correlation", "fusion", "connectors"):
        require(all(port.get("host_ip") in {"127.0.0.1", "::1"} for port in services[name].get("ports", [])),
                f"{name}: publishes a host listener outside loopback")
    for name in ("tkg-sync", "tkg-reconcile"):
        require(not services[name].get("ports"), f"{name}: publishes a host port")
        require(services[name]["image"] == services["api"]["image"] and not services[name].get("build"),
                f"{name}: must reuse the API image")
        require(services[name].get("cpus") and services[name].get("mem_limit"), f"{name}: missing resource limits")
    require(services["agents"]["environment"].get("AISOC_TKG_RECON_PROFILE") in {"standard", "deep_case"},
            "Invalid Recon profile")
    worker = services["tkg-sync"]["environment"]
    reconciler = services["tkg-reconcile"]["environment"]
    if reconciler.get("AISOC_TKG_RECONCILE_ENABLED", "").lower() in {"true", "1", "yes", "on"}:
        worker_user = urlsplit(worker.get("DATABASE_URL", "")).username
        reconcile_user = urlsplit(reconciler.get("AISOC_TKG_RECONCILE_DATABASE_URL", "")).username
        require(reconcile_user and reconcile_user != worker_user, "Reconciler must use its own database role")
    for name in ("api", "agents", "tkg-sync", "tkg-reconcile"):
        mounts = {m.get("target"): m for m in services[name].get("volumes", [])}
        role = {"tkg-sync": "ingest", "tkg-reconcile": "diagnostics"}.get(name, "reader")
        require(mounts.get(f"/run/secrets/tkg/{role}", {}).get("read_only"), f"{name}: TKG role mount is missing or writable")
        require(
            {path for path in mounts if path.startswith("/run/secrets/tkg/")} == {f"/run/secrets/tkg/{role}"},
            f"{name}: unexpected TKG credential mount",
        )
        if private_ca:
            require(mounts.get("/run/ca/tkg.pem", {}).get("read_only"), f"{name}: TKG private CA mount is missing or writable")
    print("Compose qualification passed. Existing environments, mounts, networks and dependencies were preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tkg-checkout", type=Path, required=True)
    parser.add_argument("--runtime-override", type=Path, required=True)
    parser.add_argument("--soc-env", type=Path)
    parser.add_argument("--tkg-env", type=Path)
    parser.add_argument("--private-ca", action="store_true")
    args = parser.parse_args()
    soc = Path(__file__).resolve().parents[1]
    before_files = (*SOC_OVERRIDES, args.runtime_override.resolve())
    tkg_files = ("infra/compose/tkg-network.override.yml",)
    if args.private_ca:
        tkg_files += ("infra/compose/tkg-ca.override.yml",)
    before = resolve(soc, before_files, args.soc_env, "aisoc-demo")
    after = resolve(soc, (*SOC_OVERRIDES, *tkg_files, args.runtime_override.resolve()), args.soc_env, "aisoc-demo")
    tkg = resolve(args.tkg_checkout.resolve(), TKG_OVERRIDES, args.tkg_env, "soorin-tkg-server55", profile="models")
    validate(before, after, tkg, private_ca=args.private_ca)


if __name__ == "__main__":
    main()
