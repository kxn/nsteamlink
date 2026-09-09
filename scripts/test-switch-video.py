#!/usr/bin/env python3
"""Deploy an embedded-fixture probe and collect results without screen feedback."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time


def result_from_log(text):
    begins = list(re.finditer(r'^\[(\d+) startup\] PROBE_BEGIN build=(\S+)', text, re.M))
    result = {'result': 'INCOMPLETE', 'resources_clean': False, 'loader_return': 'unverified'}
    if not begins:
        return result
    run = begins[-1].group(1)
    result.update(run=run, build=begins[-1].group(2))
    result['sdk_errors'] = re.findall(
        r'^\[' + run + r' [^\]]+\] deko result=([1-9]\d*) where=(\S+) message=(.*)$', text, re.M)
    final = re.search(r'^\[' + run + r' complete\] PROBE_FINAL result=(PASS|FAIL) failed_stage=(\S+)', text, re.M)
    if final:
        result.update(result=final.group(1), failed_stage=final.group(2))
    result['resources_clean'] = bool(re.search(r'^\[' + run + r' complete\] PROBE_CLEANUP resources=clean transport=closing$', text, re.M))
    stages = re.findall(r'^\[' + run + r' [^\]]+\] STAGE=(\S+)', text, re.M)
    if stages:
        result['last_stage'] = stages[-1]
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=Path('build/switch-deko'))
    p.add_argument('--address', default='10.10.10.17')
    p.add_argument('--fixture', choices=['padding720', 'padding1080', 'sequential', 'reordered'], default='padding720')
    p.add_argument('--timeout', type=float, default=120)
    a = p.parse_args()
    nro = a.build / 'app/nsl-video-probe.nro'
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    directory = a.build / 'probe-runs' / stamp
    directory.mkdir(parents=True)
    nxlink = shutil.which('nxlink') or '/opt/devkitpro/tools/bin/nxlink'
    command = [nxlink, '-a', a.address, '-r', '3', '-s', str(nro), '--args', a.fixture]
    if shutil.which('stdbuf'):
        command = ['stdbuf', '-oL', '-eL', *command]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    chunks = []
    timed_out = False
    try:
        with selectors.DefaultSelector() as selector, (directory / 'console.log').open('wb') as log:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + a.timeout
            while selector.get_map():
                if time.monotonic() >= deadline:
                    timed_out = True
                    process.terminate()
                    break
                for key, _ in selector.select(timeout=min(1, max(0, deadline-time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    chunks.append(data)
                    log.write(data)
                    log.flush()
                    print(data.decode('utf-8', errors='replace'), end='', flush=True)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
    result = result_from_log(b''.join(chunks).decode('utf-8', errors='replace'))
    result.update(timed_out=timed_out, nxlink_exit=process.returncode, fixture=a.fixture,
                  nro_sha256=hashlib.sha256(nro.read_bytes()).hexdigest(), address=a.address)
    (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    for manifest in ['graphics_manifest.json', 'build_identity.json']:
        source = a.build / 'generated' / manifest
        if source.exists():
            shutil.copyfile(source, directory / manifest)
    print('\nResult: ' + json.dumps(result, ensure_ascii=False))
    print('Evidence: ' + str(directory.resolve()))
    return 0 if result['result'] == 'PASS' and result['resources_clean'] and not result.get('sdk_errors') and not timed_out and process.returncode == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
