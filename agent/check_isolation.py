"""Isolation check for the agent container (Day 5).

Normal mode runs inside the isolated agent container.
It exits with code 0 only if every check passes.

Control mode (--control) runs in a container that is NOT isolated.
It proves the internet probes can really succeed, so a pass in normal
mode means something.
"""
import json
import os
import socket
import sys
import time
import urllib.request

GATEWAY_HOST = "gateway"
GATEWAY_PORT = 8000
INTERNET_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)]
EXTERNAL_NAME = "example.com"
HOST_NAME = "host.docker.internal"
SECRET_WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
# The official Python image sets GPG_KEY to a public key id. It is not a secret.
ALLOWED_ENV = {"GPG_KEY"}
WRITE_PROBE = "/app/.write_probe"


def can_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def name_resolves(name: str) -> bool:
    try:
        socket.getaddrinfo(name, 443)
        return True
    except OSError:
        return False


def wait_for_gateway(max_seconds: int = 30) -> bool:
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
        if can_connect(GATEWAY_HOST, GATEWAY_PORT):
            return True
        time.sleep(1)
    return False


def gateway_health_ok() -> bool:
    url = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
            return bool(json.loads(resp.read()).get("status") == "ok")
    except (OSError, ValueError):
        return False


def secret_like_env_names() -> list[str]:
    found = []
    for name in os.environ:
        if name in ALLOWED_ENV:
            continue
        if any(word in name.upper() for word in SECRET_WORDS):
            found.append(name)
    return found


def can_write_file(path: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.remove(path)
        return True
    except OSError:
        return False


def run_checks() -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []

    results.append(("gateway port reachable", wait_for_gateway()))
    results.append(("gateway /healthz answers ok", gateway_health_ok()))

    for host, port in INTERNET_TARGETS:
        blocked = not can_connect(host, port)
        results.append((f"internet blocked: {host}:{port}", blocked))

    results.append((f"external DNS blocked: {EXTERNAL_NAME}", not name_resolves(EXTERNAL_NAME)))
    results.append(("docker host not reachable", not can_connect(HOST_NAME, 8000)))

    leaked = secret_like_env_names()
    results.append((f"no secret like env vars {leaked}", not leaked))

    if hasattr(os, "getuid"):
        results.append(("not running as root", os.getuid() != 0))

    results.append(("filesystem is read only", not can_write_file(WRITE_PROBE)))
    return results


def run_control() -> int:
    reachable = [t for t in INTERNET_TARGETS if can_connect(*t)]
    print(f"internet targets reachable from control: {reachable}")
    if reachable:
        print("CONTROL OK: the probes can reach the internet from here.")
        print("So a blocked result inside the agent container is meaningful.")
        return 0
    print("CONTROL FAILED: no internet from here either.")
    print("The isolation result proves nothing until your own network works.")
    return 1


def main() -> int:
    if "--control" in sys.argv:
        return run_control()

    results = run_checks()
    for name, passed in results:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")

    if all(passed for _, passed in results):
        print("ISOLATION OK")
        return 0
    print("ISOLATION FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())