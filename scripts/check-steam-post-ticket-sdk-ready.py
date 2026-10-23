#!/usr/bin/env python3
"""Check that asynchronous old SDK startup cannot accept a new control ticket.

The frozen original active-Test programs supply manager states 4 (authorization)
and 5 (resumed request awaiting its ticket). Native deliberately delays its SDK
ready provider until either state, then starts/joins a real IHS Test worker on a
bounded pending datagram provider. This is a port-specific asynchronous lifetime
mapping, not execution of original BInit/Qt threads or real Steam/SDR/Switch.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('post_ticket_control', ROOT / 'scripts/check-steam-post-ticket-authorization.py')
control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)


def main():
    if not __debug__: raise RuntimeError('comparison requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receiver', type=Path, required=True)
    p.add_argument('--observations', type=Path)
    args = p.parse_args(); reference = control.reference()
    differences = []; observations = []
    for outcome, resume in (('compat', False), ('compat', True), ('key', True)):
        c = next(c for c in reference['cases'] if c['testing'] and c['transport'] == 4
                 and c['schedule'] == 'active_test' and c['outcome'] == outcome)
        first = c['commands'][0]
        second = c['commands'][1]
        cm, udp = list(second[1]), list(second[2])
        if resume:
            reply = c['commands'][c['reply_index']]
            assert reply[0] == 'mixed'
            cm += reply[1]; udp += reply[2]
        phase = c['rows'][c['reply_index'] if resume else c['auth_index']]['control']['state']
        assert phase == (5 if resume else 4)
        lines = [(';'.join(a) or '-')+' '+(';'.join(b) or '-')
                 for a, b in ((first[1], first[2]), (cm, udp))]
        run = subprocess.run([str(args.receiver.resolve()), '1', '12' if resume else '11', '0'],
                             input='\n'.join(lines)+'\n', text=True, capture_output=True, timeout=10)
        label = (outcome, resume)
        assert run.returncode == 0, (label, run.returncode, run.stderr[-3000:])
        got = json.loads(run.stdout.splitlines()[-1])
        want = dict(initial_state=6, initial_sessions=0, authorizing_state=phase,
                    ready_state=phase, sessions=1, joins=1, backends=1, clean=True)
        if got != want: differences.append(dict(case=label, got=got, want=want))
        observations.append(dict(case=label, actual=got))
    if args.observations: args.observations.write_text(json.dumps(observations, indent=2)+'\n')
    assert not differences, differences
    print('PASS 3 old-SDK ready mappings: authorization/key/no-key resume phases retained; '
          'one real IHS worker joined before backend destruction')


if __name__ == '__main__': main()
