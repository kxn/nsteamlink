#!/usr/bin/env python3
"""Analyze bounded render-rate phases and cumulative vq diagnostics."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('video_perf', Path(__file__).with_name('analyze-video-perf.py'))
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)


def queue_summary(text, warmup=5):
    groups = {}
    for line in text.splitlines():
        m = re.fullmatch(r'vq([1-7]) (.*)', line)
        if not m:
            continue
        row = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', m[2])}
        if 'id' in row:
            groups.setdefault(m[1], []).append(row)
    out = {}
    for kind, rows in groups.items():
        totals, elapsed, previous, origin = {}, 0, None, None
        for row in rows:
            if origin is None:
                origin = row['id']
            old, previous = previous, row
            if old is None or old['id'] - origin < warmup * 1000:
                continue
            dt = row['id'] - old['id']
            if dt <= 0:
                continue
            # Maxima and service return codes are not cumulative counters.
            keys = row.keys() & old.keys() - {'id', 'rc', 'wmax', 'xmax', 'gapmax', 'tmax'}
            delta = {k: row[k] - old[k] for k in keys}
            if kind == '7' and (row.get('rc') != 0 or old.get('rc') != 0):
                continue
            if any(v < 0 for v in delta.values()):
                origin = row['id']
                continue
            elapsed += dt
            for k, v in delta.items():
                totals[k] = totals.get(k, 0) + v
        out['vq' + kind] = {'ms': elapsed, 'delta': totals, 'last': rows[-1]}
    return out


def analyze(text):
    markers = list(re.finditer(r'^render-rate-test (?:phase=\d+.*|end .*|abort .*)$', text, re.M))
    ranges = [(m[0], text[m.end():markers[i+1].start() if i+1 < len(markers) else len(text)],
               i+1 < len(markers)) for i, m in enumerate(markers) if 'phase=' in m[0]]
    if not ranges:
        ranges = [('unsegmented', text, False)]
    result = []
    for marker, chunk, closed in ranges:
        p = perf.summarize(chunk, 5)
        q = queue_summary(chunk)
        def rate(group, key):
            g = q.get(group, {})
            return g.get('delta', {}).get(key, 0) * 1000 / g['ms'] if g.get('ms') else None
        def ratio(group, numerator, denominator, scale=1):
            d = q.get(group, {}).get('delta', {})
            return d.get(numerator, 0) / d[denominator] * scale if d.get(denominator) else None
        result.append({'marker': marker, 'closed': closed, 'video': p, 'queue': q,
            'summary': {
                'draws_per_s': p['totals']['draws'] * 1000 / p['measured_ms'] if p['measured_ms'] else None,
                'new_per_s': p['fps'], 'attempts_per_s': rate('vq1', 'attempts'),
                'no_batch_per_s': rate('vq1', 'nobatch'), 'loops_per_s': rate('vq6', 'loops'),
                'acquire_ms': ratio('vq1', 'acquire_us', 'acquire', .001),
                'batch_residence_ms': ratio('vq2', 'residence_us', 'done', .001),
                'gpu_output_wait_ms': ratio('vq3', 'wait_ns', 'n', .000001),
                'gpu_after_wait_ms': ratio('vq3', 'work_ns', 'n', .000001),
                'main_thread_one_core_percent': ratio('vq7', 'cpu', 'wall', 100),
                'empty_takes_per_s': rate('vq4', 'empty'), 'multiple_publications_per_take_s': rate('vq4', 'many')
            }})
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = analyze(args.log.read_text(errors='replace'))
    output = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(output)
    for phase in result:
        print(phase['marker'], 'closed=' + str(phase['closed']))
        print(json.dumps(phase['summary'], ensure_ascii=False))
