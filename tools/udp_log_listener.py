#!/usr/bin/env python3
"""UDP live log listener for nsteamlink (port 28773).
Usage: python3 tools/udp_log_listener.py [outfile]"""
import socket, sys, time

PORT = 28773
out_path = sys.argv[1] if len(sys.argv) > 1 else None
out = open(out_path, "a", buffering=1) if out_path else None

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, SO_REUSEADDR := socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT))
print(f"listening udp:{PORT} -> {out_path or 'stdout'}", flush=True)
while True:
    data, addr = s.recvfrom(2048)
    line = data.decode(errors="replace").rstrip("\n")
    stamp = time.strftime("%H:%M:%S")
    print(f"{stamp} {line}", flush=True)
    if out:
        out.write(f"{stamp} {line}\n")
