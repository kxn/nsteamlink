#!/usr/bin/env python3
"""Build a key-free, plaintext template, NOT an installable NSP."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess


def pfs_files(data):
    magic, count, strings, _ = struct.unpack_from('<4sIII', data)
    assert magic == b'PFS0' and count < 100
    base = 16 + count * 24 + strings
    for i in range(count):
        offset, size, _, _ = struct.unpack_from('<QQII', data, 16 + i * 24)
        assert base + offset + size <= len(data)
        yield data[base + offset:base + offset + size]


def loader_config(root):
    config = json.loads((root / 'packaging/switch/application.json').read_text())
    for field in ('program_id', 'program_id_range_min', 'program_id_range_max'):
        config[field] = '0x01004e534c4b1000'
    # A loader needs process-code mapping permissions beyond the application's own SVC set.
    upstream = json.loads((root / 'third_party/nx-hbloader/hbl.json').read_text())
    reference = next(k['value'] for k in upstream['kernel_capabilities'] if k['type'] == 'syscalls')
    syscalls = next(k['value'] for k in config['kernel_capabilities'] if k['type'] == 'syscalls')
    for name in ('svcSetProcessMemoryPermission', 'svcMapProcessCodeMemory', 'svcUnmapProcessCodeMemory'):
        syscalls[name] = reference[name]
    return config


def main():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--hacbrewpack', required=True)
    a = p.parse_args()
    root = a.root.resolve()
    work = a.output.resolve().parent / 'shortcut-build'
    work.mkdir(parents=True, exist_ok=True)
    source = work / 'source'
    source.mkdir(exist_ok=True)
    original = (root / 'third_party/nx-hbloader/source/main.c').read_text()
    original = original.replace('"sdmc:/hbmenu.nro"', '"sdmc:/switch/nsteamlink/nsteamlink.nro"')
    needle = "if (g_nextNroPath[0] == '\\0')\n    {"
    assert original.count(needle) == 1
    original = original.replace(needle, "static bool launched = false;\n    " + needle +
        "\n        if (launched) svcExitProcess();\n        launched = true;")
    missing = 'diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 3));'
    assert original.count(missing) == 1
    original = original.replace(missing, 'svcExitProcess();')
    (source / 'main.c').write_text(original)
    shutil.copyfile(root / 'third_party/nx-hbloader/source/trampoline.s', source / 'trampoline.s')
    shutil.copyfile(root / 'third_party/nx-hbloader/Makefile', work / 'Makefile')
    config = loader_config(root)
    tid = config['program_id'].removeprefix('0x')
    (work / 'hbl.json').write_text(json.dumps(config))
    subprocess.run(['make', '-j2', 'RELEASE=1'], cwd=work, check=True, stdout=subprocess.DEVNULL)
    for name in ('exefs', 'control', 'out'):
        (work / name).mkdir(exist_ok=True)
    shutil.copyfile(work / 'hbl.nso', work / 'exefs/main')
    shutil.copyfile(work / 'hbl.npdm', work / 'exefs/main.npdm')
    tools = Path(os.environ.get('DEVKITPRO', '/opt/devkitpro')) / 'tools/bin'
    subprocess.run([str(tools / 'nacptool'), '--create', 'NSteamLink', 'kxn', '1.0.0',
                    str(work / 'control/control.nacp')], check=True)
    shutil.copyfile(root / 'assets/branding/icon.jpg', work / 'control/icon_AmericanEnglish.dat')
    # Public synthetic test vector. This is deliberately not a production keyset.
    fake_key = bytes(range(32))
    (work / 'synthetic.keys').write_text('header_key = ' + fake_key.hex() +
        '\nkey_area_key_application_00 = ' + bytes(range(16)).hex() + '\n')
    tool = shutil.which(a.hacbrewpack)
    if not tool:
        raise SystemExit('Run scripts/setup-switch-deps.sh --packager-only; set HACBREWPACK')
    subprocess.run([tool, '-k', str(work / 'synthetic.keys'), '--titleid', tid,
        '--nspdir', str(work / 'out'), '--noromfs', '--nologo', '--plaintext', '--keygeneration', '1'],
        cwd=work, check=True, stdout=subprocess.DEVNULL)
    parts = {}
    for file in pfs_files((work / 'out' / (tid + '.nsp')).read_bytes()):
        data = bytearray(file)
        for sector in range(6):
            dec = Cipher(algorithms.AES(fake_key), modes.XTS(sector.to_bytes(16, 'big'))).decryptor()
            data[sector*512:(sector+1)*512] = dec.update(data[sector*512:(sector+1)*512]) + dec.finalize()
        assert data[0x200:0x204] == b'NCA3'
        assert struct.unpack_from('<Q', data, 0x210)[0] == int(tid, 16)
        assert data[0x404] == 1
        data[0x300:0x340] = bytes(64)  # Plaintext sections have no key area.
        parts[data[0x205]] = data
    assert set(parts) == {0, 1, 2}
    bundle = b'NSLFWD01' + struct.pack('<III', *(len(parts[k]) for k in (0, 2, 1)))
    bundle += b''.join(parts[k] for k in (0, 2, 1))
    (work / 'template.bin').write_bytes(bundle)
    with a.output.open('w') as f:
        f.write('#include <stddef.h>\nconst unsigned char sl_shortcut_template[] = {\n')
        for i in range(0, len(bundle), 32):
            f.write(','.join(str(b) for b in bundle[i:i+32]) + ',\n')
        f.write('};\nconst size_t sl_shortcut_template_size = sizeof(sl_shortcut_template);\n')
    # The synthetic NSP is not a distributable artifact.
    (work / 'out' / (tid + '.nsp')).unlink()

if __name__ == '__main__':
    main()
