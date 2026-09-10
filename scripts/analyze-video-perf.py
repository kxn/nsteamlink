#!/usr/bin/env python3
"""Summarize vp1..vp5 cumulative snapshots; optionally compare matching workloads."""
import argparse
import json
from pathlib import Path
import re


def summarize(text, warmup_seconds=5):
    rows, pending = [], {}
    for line in text.splitlines():
        match = re.fullmatch(r'vp([1-5]) (.*)', line)
        if not match:
            continue
        fields = dict(re.findall(r'(\w+)=([^ ]+)', match[2]))
        try:
            fields = {k: v if k == 'b' else int(v) for k, v in fields.items()}
            ident = fields['id']
        except (KeyError, ValueError):
            continue
        if ident not in pending:
            if len(pending) >= 16:
                pending.pop(next(iter(pending)))
            pending[ident] = {}
        pending[ident][int(match[1])] = fields
        if len(pending[ident]) == 5:
            rows.append({k: v for row in pending.pop(ident).values() for k, v in row.items()})
    required = set('id s e b hw w h dec show repl drop n prep age wait decode draws redraw begin ui present uploads bytes downloads imports maps pools busy image mapped'.split())
    rows = [r for r in rows if required <= r.keys()]
    totals = {k: 0 for k in 'show dec repl drop n prep age wait decode draws redraw begin ui present uploads bytes downloads imports'.split()}
    duration = 0
    first = previous = None
    modes = set()
    used = []
    for row in rows:
        mode = tuple(row[k] for k in ('b', 'hw', 'w', 'h'))
        key = tuple(row[k] for k in ('s', 'e', 'b', 'hw', 'w', 'h'))
        if previous is None or key != previous[0] or row['id'] <= previous[1]['id']:
            first = row['id']
            previous = key, row
            continue
        old = previous[1]
        previous = key, row
        if old['id'] - first < warmup_seconds * 1000:
            continue
        delta = {k: row[k] - old[k] for k in totals}
        if any(v < 0 for v in delta.values()):
            first = row['id']
            continue  # counter reset or non-coherent group
        for k, v in delta.items():
            totals[k] += v
        duration += row['id'] - old['id']
        modes.add(mode)
        used.extend([old, row])
    def mean_us(total, count):
        return totals[total] / totals[count] if totals[count] else None
    return {
        'complete_snapshots': len(rows), 'measured_ms': duration,
        'modes': [dict(zip(('backend', 'hardware', 'width', 'height'), mode)) for mode in sorted(modes)],
        'totals': totals,
        'fps': totals['show'] * 1000 / duration if duration else None,
        'decode_mean_us': mean_us('decode', 'dec'),
        'new_frame_prepare_mean_us': mean_us('prep', 'n'),
        'decode_to_submit_mean_us': mean_us('age', 'n'),
        'decoded_frame_wait_mean_us': mean_us('wait', 'n'),
        'begin_mean_us': mean_us('begin', 'draws'),
        'ui_mean_us': mean_us('ui', 'draws'),
        'present_call_mean_us': mean_us('present', 'draws'),
        'video_upload_bytes_per_new_frame': mean_us('bytes', 'n'),
        'resources_first': {k: used[0][k] for k in ('image', 'mapped', 'maps', 'pools', 'busy')} if used else None,
        'resources_last': {k: used[-1][k] for k in ('image', 'mapped', 'maps', 'pools', 'busy')} if used else None,
        'limits': 'No GPU execution, input-to-photon, power, or per-frame percentiles. Compare the same game/scene/rate/device settings. Resource bytes cover renderer-managed allocations, not total decoder or process memory.'
    }


def compare(current, baseline):
    if len(current['modes']) != 1 or len(baseline['modes']) != 1:
        raise ValueError('comparison requires one stable resolution/decoder/backend per log')
    for key in ('hardware', 'width', 'height'):
        if current['modes'][0][key] != baseline['modes'][0][key]:
            raise ValueError('baseline mismatch: ' + key)
    old, new = baseline['new_frame_prepare_mean_us'], current['new_frame_prepare_mean_us']
    if old is None or new is None or old <= 0:
        raise ValueError('insufficient nonzero baseline preparation samples')
    return {'prepare_saved_us_per_new_frame': old - new,
            'prepare_reduction_percent': (old - new) * 100 / old,
            'baseline': baseline,
            'causality': 'Observed difference between runs; matching metadata alone does not prove identical gameplay or network load.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--warmup-seconds', type=float, default=5)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.warmup_seconds < 0:
        parser.error('warmup must be nonnegative')
    result = summarize(args.log.read_text(errors='replace'), args.warmup_seconds)
    if not result['measured_ms']:
        parser.error('no complete measurable vp1..vp5 windows; old stats-only logs cannot recover these timings')
    if args.baseline:
        result['comparison'] = compare(result, summarize(args.baseline.read_text(errors='replace'), args.warmup_seconds))
    output = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(output)
    print(output, end='')


if __name__ == '__main__':
    main()
