"""Proves the agent container is isolated.
Expected: gateway reachable, internet NOT reachable.
"""
import socket
import sys


def can_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main() -> int:
    gateway_ok = can_connect("gateway", 8000)
    internet_ok = can_connect("1.1.1.1", 443)

    print(f"gateway reachable : {gateway_ok} (expected True)")
    print(f"internet reachable: {internet_ok} (expected False)")

    if gateway_ok and not internet_ok:
        print("ISOLATION OK")
        return 0
    print("ISOLATION FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())