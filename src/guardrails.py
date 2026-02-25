import argparse
import re
import sys
from pathlib import Path

import yaml

SECRET_LIKE = re.compile(r"(token|secret|password|api[_-]?key)", re.IGNORECASE)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _env_items(environment):
    if not environment:
        return []
    if isinstance(environment, dict):
        return list(environment.items())
    items = []
    for item in environment:
        if "=" in str(item):
            key, value = str(item).split("=", 1)
            items.append((key, value))
    return items


def validate_compose(compose_data):
    violations = []
    services = compose_data.get("services", {})
    networks = compose_data.get("networks", {})

    for name, service in services.items():
        if service.get("read_only") is not True:
            violations.append(f"{name}: read_only must be true")

        cap_drop = [str(item).upper() for item in _as_list(service.get("cap_drop"))]
        if "ALL" not in cap_drop:
            violations.append(f"{name}: cap_drop must include ALL")

        security_opt = [str(item) for item in _as_list(service.get("security_opt"))]
        if "no-new-privileges:true" not in security_opt:
            violations.append(f"{name}: missing no-new-privileges:true")
        if not any(opt.startswith("seccomp=") for opt in security_opt):
            violations.append(f"{name}: missing seccomp profile in security_opt")
        if not any(opt.startswith("apparmor=") for opt in security_opt):
            violations.append(f"{name}: missing apparmor profile in security_opt")

        tmpfs = [str(item) for item in _as_list(service.get("tmpfs"))]
        tmp_entry = next((item for item in tmpfs if item.startswith("/tmp")), "")
        if not tmp_entry:
            violations.append(f"{name}: tmpfs must include /tmp")
        elif "noexec" not in tmp_entry or "nosuid" not in tmp_entry:
            violations.append(f"{name}: /tmp tmpfs must include noexec,nosuid")

        if not service.get("pids_limit"):
            violations.append(f"{name}: pids_limit is required")
        if not service.get("mem_limit"):
            violations.append(f"{name}: mem_limit is required")

        service_secrets = _as_list(service.get("secrets"))
        if not service_secrets:
            violations.append(f"{name}: at least one secret must be configured")

        for key, value in _env_items(service.get("environment")):
            if key.endswith("_FILE"):
                continue
            if SECRET_LIKE.search(key) and value:
                violations.append(
                    f"{name}: env '{key}' looks like an inline secret; "
                    "use *_FILE with Docker secrets"
                )

        service_networks = _as_list(service.get("networks"))
        for network_name in service_networks:
            network_config = networks.get(network_name, {})
            if network_config.get("internal") is not True:
                violations.append(f"{name}: network '{network_name}' must be internal")

    if not compose_data.get("secrets"):
        violations.append("top-level secrets definition is required")

    return violations


def load_yaml(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate Docker sandbox hardening guardrails.")
    parser.add_argument("compose_file", help="Path to docker-compose YAML file")
    args = parser.parse_args(argv)

    compose_data = load_yaml(args.compose_file)
    violations = validate_compose(compose_data)
    if violations:
        for violation in violations:
            print(f"FAIL: {violation}")
        return 1

    print("PASS: all sandbox hardening guardrails satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
