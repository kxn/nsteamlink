#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
spec = importlib.util.spec_from_file_location('compiler', Path(__file__).with_name('compile-i18n.py'))
compiler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compiler)
with tempfile.TemporaryDirectory() as tmp:
    source = Path(tmp)
    for invalid in ({'TITLE': '%s'}, {'TITLE': '%n'}, {'OTHER': '%d'}, {'TITLE': ''}):
        (source / 'zh-CN.json').write_text(json.dumps({'TITLE': '%d'}))
        (source / 'en.json').write_text(json.dumps(invalid))
        try:
            compiler.compile_catalogs(source, source / 'out')
        except ValueError:
            pass
        else:
            raise AssertionError(f'invalid translation accepted: {invalid}')
    (source / 'en.json').write_text('{"TITLE":"%d", "TITLE":"%d"}')
    try:
        compiler.compile_catalogs(source, source / 'out')
    except ValueError:
        pass
    else:
        raise AssertionError('duplicate resource accepted')
print('PASS catalog validation rejects missing keys and unsafe format changes')
