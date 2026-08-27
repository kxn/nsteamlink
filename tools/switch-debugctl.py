#!/usr/bin/env python3
"""Send development commands to switch-discover's UDP debug port."""

import argparse
import socket
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Switch IP address")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command and arguments")
    parser.add_argument("--port", type=int, default=28772, help="debug UDP port")
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds to wait per try")
    parser.add_argument("--retries", type=int, default=3, help="number of send attempts")
    args = parser.parse_args()

    command = " ".join(args.command).strip()
    if not command:
        parser.error("missing command")

    payload = command.encode("ascii", errors="strict")
    address = (args.host, args.port)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        last_error: Exception | None = None
        for _ in range(max(args.retries, 1)):
            try:
                sock.sendto(payload, address)
                data, _ = sock.recvfrom(8192)
                print(data.decode("utf-8", errors="replace"))
                return 0
            except socket.timeout as exc:
                last_error = exc
                continue
            except OSError as exc:
                last_error = exc
                break

    print(f"no response from {args.host}:{args.port}: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
