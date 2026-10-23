#!/usr/bin/env python3
"""Actual DNS + TLS sockets: transport failover, CA/SNI, no partial-body replay."""
import argparse
from collections import Counter
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--receiver', required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='nsl-http-route-') as directory:
    root = Path(directory)
    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/'ca.key', '-out', root/'ca.pem', '-days', '1', '-subj', '/CN=NSL Test CA')
    contexts = {}
    for name, host in [('good', 'route.test'), ('bad', 'wrong.test')]:
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/f'{name}.key', '-out', root/f'{name}.csr', '-subj', f'/CN={host}')
        (root/'ext').write_text(f'subjectAltName=DNS:{host}\n')
        openssl('x509', '-req', '-in', root/f'{name}.csr', '-CA', root/'ca.pem', '-CAkey', root/'ca.key', '-CAcreateserial', '-out', root/f'{name}.pem', '-days', '1', '-extfile', root/'ext')
        contexts[name] = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexts[name].load_cert_chain(root/f'{name}.pem', root/f'{name}.key')
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(('127.0.0.1', 0)); dns.settimeout(.1)
    stop = threading.Event()
    counts = Counter()
    answers = []
    drop_dns = False
    threads, listeners = [], []
    def resolve():
        while not stop.is_set():
            try: packet, peer = dns.recvfrom(512)
            except socket.timeout: continue
            if drop_dns: continue
            header = packet[:2] + b'\x81\x80' + struct.pack('!HHHH', 1, len(answers), 0, 0)
            response = header + packet[12:]
            for ip in answers:
                response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton(ip)
            dns.sendto(response, peer)
    thread = threading.Thread(target=resolve); thread.start(); threads.append(thread)
    # Independent late/silent providers. A delayed reply is scheduled without
    # serialising subsequent DNS datagrams on a fixture thread.
    extra_dns = []
    def extra_resolve(sock, silent):
        pending = []
        while not stop.is_set():
            try:
                packet, peer = sock.recvfrom(512)
                if not silent:
                    response = packet[:2] + b'\x81\x80' + struct.pack('!HHHH', 1, 1, 0, 0) + packet[12:]
                    response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('127.0.3.1')
                    pending.append((time.monotonic() + .6, response, peer))
            except socket.timeout: pass
            now = time.monotonic()
            for deadline, response, peer in pending[:]:
                if now >= deadline:
                    sock.sendto(response, peer)
                    pending.remove((deadline, response, peer))
    for silent in [False, True]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0)); sock.settimeout(.01); extra_dns.append(sock)
        thread = threading.Thread(target=extra_resolve, args=(sock, silent)); thread.start(); threads.append(thread)
    # Different /24s retain the intended failure order after policy interleaving.
    port = None
    def server(ip, kind):
        listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port or 0)); listener.listen(); listener.settimeout(.1)
        listeners.append(listener)
        def serve():
            while not stop.is_set():
                try: conn, _ = listener.accept()
                except socket.timeout: continue
                counts[kind] += 1
                with conn:
                    conn.settimeout(2)
                    if kind == 'stall':
                        stop.wait(1.2); continue
                    try:
                        with contexts['bad' if kind == 'bad' else 'good'].wrap_socket(conn, server_side=True) as tls:
                            request = tls.recv(8192)
                            if not request: continue  # Client rejected the certificate.
                            assert b'Host: route.test:' in request, request
                            if kind == 'http': tls.sendall(b'HTTP/1.1 503 Busy\r\nContent-Length: 2\r\nConnection: close\r\n\r\nNO')
                            elif kind == 'partial': tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nNO')
                            else: tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                    except (ssl.SSLError, OSError): pass
        t = threading.Thread(target=serve); t.start(); threads.append(t)
        return listener.getsockname()[1]
    port = server('127.0.1.1', 'stall')
    server('127.0.2.1', 'bad'); server('127.0.3.1', 'good')
    server('127.0.4.1', 'http'); server('127.0.5.1', 'partial')
    def run(mode, expected, ips, progressive=False):
        answers[:] = ips
        before = counts.copy()
        dns_arg = ','.join(str(s.getsockname()[1]) for s in [dns, *extra_dns]) if progressive else str(dns.getsockname()[1])
        result = subprocess.run([a.receiver, dns_arg, f'https://route.test:{port}/directory', str(root/'ca.pem'), mode, expected], text=True, capture_output=True, timeout=12)
        assert result.returncode == 0, result.stdout + result.stderr
        return counts - before, result.stdout
    try:
        for mode in ['early-blocking', 'early-multi', 'early-async', 'early-async-connect-only']:
            began = time.monotonic()
            delta, output = run(mode, 'connected' if 'connect-only' in mode else 'success', ['127.0.3.1'], True)
            assert delta == Counter(good=1) and time.monotonic() - began < 2, (delta, output)
        # The first provider's only IP fails before another provider answers.
        # Keep the request pending, learn the late address, and never replay the
        # refused IP or wait for the deliberately silent third provider.
        for mode in ['late-blocking', 'late-async']:
            began = time.monotonic()
            delta, output = run(mode, 'success', ['127.0.0.2'], True)
            elapsed = time.monotonic() - began
            assert delta == Counter(good=1) and .5 < elapsed < 2, (delta, elapsed, output)
        for mode in ['blocking', 'multi', 'connect-only', 'async', 'async-connect-only']:
            delta, output = run(mode, 'connected' if 'connect-only' in mode else 'success', ['127.0.0.2', '127.0.1.1', '127.0.2.1', '127.0.3.1'])
            assert delta == Counter(stall=1, bad=1, good=1), (delta, output)
        delta, output = run('multi', 'failure', ['127.0.2.1'])
        assert delta == Counter(bad=1) and 'curl=60' in output, (delta, output)
        for kind, ip in [('http', '127.0.4.1'), ('partial', '127.0.5.1')]:
            for mode in ['blocking', 'multi']:
                delta, output = run(mode, kind, [ip, '127.0.3.1'])
                assert delta == Counter({kind: 1}), (delta, output)
        drop_dns = True
        for mode in ['dns-cancel', 'dns-fail']:
            delta, output = run(mode, 'failure', ['127.0.3.1'])
            assert not delta, (delta, output)
        drop_dns = False
        for mode in ['cancel', 'deadline']:
            delta, output = run(mode, 'failure', ['127.0.0.2', '127.0.3.1'])
            assert not delta, (delta, output)
        print('PASS: first DNS answer starts TLS before a silent provider finishes; late DNS fallback; blocking/multi TCP refusal -> TLS timeout -> wrong certificate -> verified HTTPS; HTTP/partial-body never replayed; cancellation/deadline stop retries')
    finally:
        stop.set()
        for t in threads: t.join()
        for listener in listeners: listener.close()
        dns.close()
        for sock in extra_dns: sock.close()
