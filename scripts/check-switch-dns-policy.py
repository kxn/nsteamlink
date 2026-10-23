#!/usr/bin/env python3
"""Verify actual linked Switch DNS/curl callers, not merely source intent."""
import argparse
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('build', type=Path)
a = p.parse_args()
build = a.build.resolve()
cache = (build / 'CMakeCache.txt').read_text()
m = re.search(r'^CMAKE_OBJDUMP:[^=]+=(.+)$', cache, re.M)
assert m, 'configured cross objdump is required'
elf = build / 'app/nsteamlink.elf'
caller, calls = '', []
process = subprocess.Popen([m[1], '-d', str(elf)], stdout=subprocess.PIPE, text=True)
for line in process.stdout:
    symbol = re.match(r'^\w+ <(.*)>:', line)
    if symbol:
        caller = symbol[1]
    call = re.search(r'\b(?:bl|b)\s+\w+ <((?:__wrap_)?(?:getaddrinfo|curl_easy_init)|gethostbyname|curl_easy_duphandle)>', line)
    if call:
        calls.append({'caller': caller, 'callee': call[1]})
assert process.wait() == 0
for name, adapter in [('getaddrinfo', '__wrap_getaddrinfo'), ('curl_easy_init', '__wrap_curl_easy_init')]:
    assert any(c['callee'] == adapter for c in calls), f'{adapter} unused'
    assert all(c['caller'] == adapter for c in calls if c['callee'] == name), f'direct {name} call remains'
assert not any(c['callee'] in ('gethostbyname', 'curl_easy_duphandle') for c in calls), 'unaudited resolver/factory entry'
assert any(c['caller'] == 'Curl_getaddrinfo_ex' and c['callee'] == '__wrap_getaddrinfo' for c in calls), 'curl resolver bypasses policy'
if 'NSL_BUILD_SNS:BOOL=ON' in cache:
    assert any('ResolveHostname' in c['caller'] and c['callee'] == '__wrap_getaddrinfo' for c in calls), 'SDK resolver bypasses policy'
    assert any('begin_config' in c['caller'] and c['callee'] == '__wrap_curl_easy_init' for c in calls), 'SDR HTTP factory bypasses policy'
print(json.dumps({'pass': True, 'callers': calls}, indent=2))
