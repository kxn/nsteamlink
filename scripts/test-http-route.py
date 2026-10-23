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
    threads, listeners = [], []
    def resolve():
        while not stop.is_set():
            try: packet, peer = dns.recvfrom(512)
            except socket.timeout: continue
            header = packet[:2] + b'\x81\x80' + struct.pack('!HHHH', 1, len(answers), 0, 0)
            response = header + packet[12:]
            for ip in answers:
                response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton(ip)
            dns.sendto(response, peer)
    thread = threading.Thread(target=resolve); thread.start(); threads.append(thread)
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
    def run(mode, expected, ips):
        answers[:] = ips
        before = counts.copy()
        result = subprocess.run([a.receiver, str(dns.getsockname()[1]), f'https://route.test:{port}/directory', str(root/'ca.pem'), mode, expected], text=True, capture_output=True, timeout=12)
        assert result.returncode == 0, result.stdout + result.stderr
        return counts - before, result.stdout
    try:
        for mode in ['blocking', 'multi', 'connect-only']:
            delta, output = run(mode, 'connected' if mode == 'connect-only' else 'success', ['127.0.0.2', '127.0.1.1', '127.0.2.1', '127.0.3.1'])
            assert delta == Counter(stall=1, bad=1, good=1), (delta, output)
        delta, output = run('multi', 'failure', ['127.0.2.1'])
        assert delta == Counter(bad=1) and 'curl=60' in output, (delta, output)
        for kind, ip in [('http', '127.0.4.1'), ('partial', '127.0.5.1')]:
            for mode in ['blocking', 'multi']:
                delta, output = run(mode, kind, [ip, '127.0.3.1'])
                assert delta == Counter({kind: 1}), (delta, output)
        for mode in ['cancel', 'deadline']:
            delta, output = run(mode, 'failure', ['127.0.0.2', '127.0.3.1'])
            assert not delta, (delta, output)
        print('PASS: blocking/multi TCP refusal -> TLS timeout -> wrong certificate -> verified HTTPS; HTTP/partial-body never replayed; cancellation/deadline stop retries')
    finally:
        stop.set()
        for t in threads: t.join()
        for listener in listeners: listener.close()
        dns.close()
