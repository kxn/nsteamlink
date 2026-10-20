#!/usr/bin/env python3
"""Require normally executing wrong production list policies to fail original vectors."""
import argparse
import ctypes as c
import gzip
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
class List(c.Structure):
    _fields_=[('ids',c.POINTER(c.c_uint64)),('count',c.c_size_t),('capacity',c.c_size_t)]

def check(lib,r):
    dll=c.CDLL(str(lib))
    for name in ['sl_accounts_status','sl_accounts_authorize','sl_accounts_pair']:
        fn=getattr(dll,name);fn.argtypes=[c.POINTER(List),c.c_uint64,c.POINTER(c.c_bool)];fn.restype=c.c_bool
    dll.sl_accounts_reserve.argtypes=[c.POINTER(List),c.c_size_t];dll.sl_accounts_reserve.restype=c.c_bool
    dll.sl_accounts_destroy.argtypes=[c.POINTER(List)]
    def program(initial,ops):
        row=List();assert dll.sl_accounts_reserve(c.byref(row),len(initial));row.count=len(initial)
        for i,value in enumerate(initial):row.ids[i]=value
        out=[]
        try:
            for name,value in ops:
                added=c.c_bool()
                assert getattr(dll,name)(c.byref(row),value,c.byref(added)),'resource/ABI failure is not a policy rejection'
                out.append(dict(added=added.value,ids=[row.ids[i] for i in range(row.count)]))
        finally:dll.sl_accounts_destroy(c.byref(row))
        return out
    mismatches=[]
    for case in r['lists']:
        fn='sl_accounts_status' if case['kind']=='status' else 'sl_accounts_pair'
        actual=program(case['initial'],[(fn,x['account']) for x in case['steps']])
        expected=[{k:x[k] for k in ('added','ids')} for x in case['steps']]
        if actual!=expected:mismatches.append(case['kind'])
    initial=[76561198000000002,76561198000000001,76561198000000003,76561198000000004]
    for case in r['auth']:
        step=case['steps'][-1]
        for client,expected in step['accounts'].items():
            ops=[('sl_accounts_authorize',e['steam']) for e in step['events'] if e['op']=='identity' and str(e['client'])==client]
            rows=program(initial,ops)
            if (rows[-1]['ids'] if rows else initial)!=expected:mismatches.append('authorize')
    return mismatches

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--compiler',required=True);a=p.parse_args()
    source=(ROOT/'app/platforms/common/host_accounts.c').read_text()
    r=json.loads(gzip.decompress((ROOT/'scripts/fixtures/steam-account-metadata-reference.json.gz').read_bytes()))
    changes={
      'status-stable-move':('list->ids[i] = list->ids[0];\n        list->ids[0] = id;',
         'memmove(list->ids + 1, list->ids, i * sizeof(*list->ids));\n        list->ids[0] = id;'),
      'authorize-stable-remove':('list->ids[i] = list->ids[--list->count];',
         '{ memmove(list->ids + i, list->ids + i + 1, (list->count - i - 1) * sizeof(*list->ids)); --list->count; }'),
      'status-keeps-zero':('if (!id) return true;','/* wrong: admit zero in status */'),
      'paired-prepends':('list->ids[list->count++] = id;',
         'memmove(list->ids + 1, list->ids, list->count++ * sizeof(*list->ids)); list->ids[0] = id;'),
    }
    with tempfile.TemporaryDirectory(prefix='nsl-account-mutations-') as directory:
        root=Path(directory)
        def compile(name,text):
            src=root/(name+'.c');lib=root/(name+'.so');src.write_text(text)
            # Compile errors, load errors, asserts or crashes never count as a rejection.
            subprocess.run([a.compiler,'-std=gnu11','-shared','-fPIC','-Wall','-Wextra','-Werror',
              '-I'+str(ROOT/'app/platforms/common'),str(src),'-o',str(lib)],check=True,capture_output=True,text=True)
            return lib
        assert not check(compile('baseline',source),r),'baseline must match the independent original reference'
        for name,(before,after) in changes.items():
            assert source.count(before)==1,(name,source.count(before))
            mismatches=check(compile(name,source.replace(before,after)),r)
            assert mismatches,(name,'wrong strategy passed')
            print(name,'normally executed; rejected by',sorted(set(mismatches)),flush=True)
    print('PASS four normally executing wrong production list policies rejected; baseline matches')
if __name__=='__main__':main()
