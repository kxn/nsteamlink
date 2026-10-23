#!/usr/bin/env python3
"""Require original traces to reject runnable address-cache/sort regressions."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

if not __debug__:
    raise SystemExit('Mutation verification requires assertions; do not use Python -O')

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', default='c++')
    p.add_argument('--c-compiler', default='cc')
    args = p.parse_args()
    source = (ROOT/'app/platforms/common/host_addresses.cpp').read_text()
    clear = '''    for (size_t i = list->count; i > 0; --i)
        if (!list->entries[i-1].verified)
            list->entries[i-1] = list->entries[--list->count];'''
    sort = '''nsl_address_sort::__introsort<nsl_address_sort::_ClassicAlgPolicy, Before&,
        sl_address_record *, false>(list->entries, list->entries+list->count, before, depth, true);'''
    edits = {
        'candidate-time-zero': ('{verified, remote, now, *address}',
                                 '{verified, remote, verified ? now : 0, *address}'),
        'announcement-confirms-route': ('if (verified) {', 'if (true) {'),
        'stable-clear': (clear, '''    size_t n = 0;
    for (size_t i = 0; i < list->count; ++i)
        if (list->entries[i].verified) list->entries[n++] = list->entries[i];
    list->count = n;'''),
        'port-is-identity': ('&address->ip)) break;',
                              '&address->ip) && list->entries[i].address.port == address->port) break;'),
        'system-stable-sort': (sort, 'std::stable_sort(list->entries, list->entries+list->count, before);'),
        'global-time-order': ('if (a.timestamp > plus_three(b.timestamp)) return true;',
                               'if (a.timestamp != b.timestamp) return a.timestamp > b.timestamp;'),
        'prefer-public-address': ('if (a.remote != b.remote) return !a.remote;',
                                  'if (a.remote != b.remote) return a.remote;'),
        'ipv4-byte-order': ('uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3]',
                            'uint32_t(b[3]) << 24 | uint32_t(b[2]) << 16 | uint32_t(b[1]) << 8 | b[0]'),
    }
    with tempfile.TemporaryDirectory(prefix='nsl-address-') as tmp:
        work = Path(tmp)
        for name in ('host_addresses.h', 'steam_address_sort.h'):
            shutil.copyfile(ROOT/'app/platforms/common'/name, work/name)
        includes = ['-I'+str(work), '-I'+str(ROOT/'third_party/ihslib/include'),
                    '-I'+str(ROOT/'third_party/ihslib/src')]
        objects = []
        for n, path in enumerate(('app/tests/address_cache_oracle.c',
                'third_party/ihslib/src/ihs_ip.c', 'third_party/ihslib/src/platforms/ihs_ip_posix.c')):
            out = work/f'{n}.o'
            result = subprocess.run([args.c_compiler, '-std=gnu11', '-UNDEBUG', *includes,
                '-c', str(ROOT/path), '-o', str(out)], capture_output=True, text=True, timeout=30)
            assert not result.returncode, result.stderr
            objects.append(str(out))
        for name, edit in [('baseline', None)]+list(edits.items()):
            if edit: assert edit[0] in source, name
            (work/'host_addresses.cpp').write_text(source if edit is None else source.replace(*edit))
            receiver = work/name
            result = subprocess.run([args.compiler, '-std=c++17', '-UNDEBUG', *includes,
                str(work/'host_addresses.cpp'), *objects, '-o', str(receiver)],
                capture_output=True, text=True, timeout=30)
            assert not result.returncode, (name, result.stderr[-2000:])
            result = subprocess.run(['python3', str(ROOT/'scripts/check-steam-address-cache.py'),
                '--receiver', str(receiver)], capture_output=True, text=True, timeout=30)
            if edit is None: assert not result.returncode, result.stderr
            else:
                # Build failures, signals and receiver assertions cannot pass
                # as proof that the original comparison rejected a result.
                assert result.returncode and 'assert got == want' in result.stderr, (name, result.stderr[-1500:])
            print('PASS', name, 'accepted' if edit is None else 'rejected by original output')


if __name__ == '__main__':
    main()
