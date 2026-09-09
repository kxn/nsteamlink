#!/usr/bin/env python3
"""Validate UTF-8 catalog parity and printf contracts, then embed immutable tables."""
import argparse
import json
import re
from pathlib import Path

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate key: {key}')
        result[key] = value
    return result

def formats(text):
    pattern = r'%(?:%|[-+ #0]*\d*(?:\.\d+)?(?:hh|ll|[hljztL])?[diuoxXfFeEgGaAcsp])'
    if '%' in re.sub(pattern, '', text):
        raise ValueError('unsupported printf placeholder')
    return re.findall(pattern, text)

def compile_catalogs(source, output):
    catalogs = [json.loads((source / f'{lang}.json').read_text(), object_pairs_hook=unique)
                for lang in ('zh-CN', 'en')]
    keys = sorted(catalogs[0])
    for catalog in catalogs:
        if set(catalog) != set(keys):
            raise ValueError('language catalog keys differ')
        for key, value in catalog.items():
            if not re.fullmatch('[A-Z][A-Z0-9_]*', key) or not isinstance(value, str) or not value or '\0' in value:
                raise ValueError(f'invalid resource: {key}')
            if len(value.encode('utf-8')) > (31 if key == 'DELETE' else 127):
                raise ValueError(f'resource exceeds UI text buffer: {key}')
            if formats(value) != formats(catalogs[0][key]):
                raise ValueError(f'printf contract differs: {key}')
            if re.match(r'^[ABXY]  ', catalogs[0][key]) and value[:3] != catalogs[0][key][:3]:
                raise ValueError(f'button binding prefix differs: {key}')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'i18n_keys.h').write_text('#pragma once\ntypedef enum sl_text_id {\n' +
        ''.join(f'    SL_T_{key},\n' for key in keys) + '    SL_T_COUNT\n} sl_text_id;\n')
    (output / 'i18n_data.h').write_text('/* Generated from app/resources/i18n. Do not edit. */\n' +
        'static const char *const translations[2][SL_T_COUNT] = {\n' +
        ',\n'.join('{\n' + ''.join(f'    [SL_T_{key}] = {json.dumps(c[key], ensure_ascii=False)},\n'
                                    for key in keys) + '}' for c in catalogs) + '\n};\n')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('source', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    compile_catalogs(args.source, args.output)
