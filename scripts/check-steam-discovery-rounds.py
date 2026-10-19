#!/usr/bin/env python3
"""Compare real Native owned discovery rounds with two original clients.

Native executes real workers, timers, receive batches, subscription changes,
UDP/protobuf serialization and stop/join/destroy. Wall time, RNG endpoints,
sendto results and broadcast enumeration are explicit controlled adapters; no
LAN/Steam/Switch or natural Qt timing claim. Random outputs separately compare
actual Native implementation with original global/vtable seeded streams.
Saved-target programs use original RequestStatus with explicitly preloaded
persistent-record and lookup terminals, not a cache/file-loading proof.
"""
import argparse
import gzip
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = {'core': '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e',
              'shell': '15b2d79881eef0c47ed2f96c17d1d60a5f42d3285abcf9f512cfffdac5b238a2'}


def require(value, why):
    if not value:
        raise ValueError(why)


def load(name):
    source = json.loads(gzip.decompress((ROOT / 'scripts/fixtures' / name).read_bytes()))
    for helper, wanted in source['helpers'].items():
        require(hashlib.sha256((ROOT / 'scripts' / helper).read_bytes()).hexdigest() == wanted,
                'Source helper identity: ' + helper)
    return source


def projection(row):
    result = {key: row[key] for key in ('sequence', 'next_status', 'fast_status',
                                       'status_tries', 'broadcast_owners')}
    result['wires'] = [x['wire'] for x in row['sends']]
    result['destinations'] = [int.from_bytes(bytes.fromhex(x['sockaddr'])[4:8], 'big')
                              for x in row['sends']]
    return result


def policies():
    source = load('steam-discovery-rounds-reference.json.gz')
    send = load('steam-discovery-send-reference.json.gz')
    result = []
    for identity, digest in IDENTITIES.items():
        binary = source['binaries'][identity]
        require(binary['sha256'] == digest and len(binary['schedules']) == 12 and
                len(binary['random']['cases']) == 7, 'pinned Source schedules/streams')
        wanted = {case['name']: [projection(row) for row in case['stages']]
                  for case in binary['schedules']}
        require(send['binaries'][identity]['binary_sha256'] == digest, 'Source send identity')
        for boundary in ('lower', 'upper'):
            case = next(c for c in send['binaries'][identity]['cases']
                        if c['name'] == 'broadcast_schedule_' + boundary)
            wanted[boundary] = [projection(row) for row in case['stages']]
        random = [{**case, 'samples': [{k: sample[k] for k in ('range', 'values')}
                   for sample in case['samples']]} for case in binary['random']['cases']]
        result.append(dict(schedules=wanted, random=random, forced=binary['random']['forced']))
    require(result[0] == result[1], 'independent original binary agreement')
    result[0]['schedules']['target-oom'] = result[0]['schedules']['targets']
    result[0]['schedules']['nested_deferred_trigger'] = result[0]['schedules']['nested_receive_trigger']
    return result[0]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--modes', help='Explicit subset; defaults to all schedule programs and RNG')
    args = p.parse_args()
    wanted = policies()
    modes = args.modes.split(',') if args.modes else [*wanted['schedules'], 'random']
    require(modes and len(set(modes)) == len(modes) and all(
        m == 'random' or m in wanted['schedules'] for m in modes), 'known unique modes')
    cases = []
    for mode in modes:
        process = subprocess.run([str(args.receiver.resolve()), mode], capture_output=True,
                                 text=True, timeout=20)
        require(process.returncode == 0, f'{mode} observation failed: {process.stderr}')
        require(not process.stderr, f'{mode} unexpected stderr: {process.stderr}')
        observed = json.loads(process.stdout)
        if mode == 'random':
            actual = dict(cases=observed['random'], forced=observed['forced'])
            expected = dict(cases=wanted['random'], forced=wanted['forced'])
        else:
            require(observed['cleanup'] is True, mode + ' completed cleanup')
            actual, expected = observed['stages'], wanted['schedules'][mode]
        cases.append(dict(mode=mode, compatible=actual == expected,
                          observed=actual, expected=expected))
    result = dict(scope=__doc__, compatible=all(c['compatible'] for c in cases), cases=cases)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    gaps = [c['mode'] for c in cases if not c['compatible']]
    print(f'Discovery rounds: {len(cases)-len(gaps)}/{len(cases)} compatible; gaps={gaps}')
    raise SystemExit(1 if gaps else 0)


if __name__ == '__main__':
    main()
