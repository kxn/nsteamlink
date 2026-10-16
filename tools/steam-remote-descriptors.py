#!/usr/bin/env python3
"""Recover the fixed Steam Link ELF's wire schemas; no process/session data is read.

Requires google.protobuf. The descriptor table layout is specific to the pinned
arm64 sample. Output includes exact descriptor bytes, a dependency-complete
FileDescriptorSet, and readable proto2 schemas suitable for protoc.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct

from google.protobuf import descriptor_pb2

SAMPLE_SHA256 = '50e1d3147d5d47b71ef1970e1867a2fe4f3e1ecf2ea6153f927fac88b88ea38e'
ROOTS = (
    'steammessages_remoteclient_discovery.proto',
    'steammessages_remoteclient_service_messages.proto',
    'steammessages_remoteplay.proto',
    'steamdatagram_messages_sdr.proto',
    'steamdatagram_messages_auth.proto',
    'steamnetworkingsockets_messages.proto',
    'steamnetworkingsockets_messages_certs.proto',
    'steamnetworkingsockets_messages_udp.proto',
)


class SampleELF:
    def __init__(self, raw):
        if hashlib.sha256(raw).hexdigest() != SAMPLE_SHA256:
            raise ValueError('ELF does not match the pinned arm64 sample')
        self.raw = raw
        if raw[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', raw, 18)[0] != 183:
            raise ValueError('expected ELF64 little-endian AArch64')
        phoff, shoff = struct.unpack_from('<QQ', raw, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', raw, 54)
        self.segments = [struct.unpack_from('<IIQQQQQQ', raw, phoff+i*phsize)
                         for i in range(phnum)]
        sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff+i*shsize)
                    for i in range(shnum)]
        self.relative = {}
        self.tables = {}
        for section in sections:
            _, kind, _, _, offset, size, link, _, _, stride = section
            if kind == 4:  # SHT_RELA
                for pos in range(offset, offset+size, stride):
                    target, info, addend = struct.unpack_from('<QQq', raw, pos)
                    if info & 0xffffffff == 1027:  # R_AARCH64_RELATIVE
                        self.relative[target] = addend
            elif kind == 11:  # SHT_DYNSYM
                strings = sections[link]
                names = raw[strings[4]:strings[4]+strings[5]]
                for pos in range(offset, offset+size, stride):
                    name, _, _, _, value, _ = struct.unpack_from('<IBBHQQ', raw, pos)
                    end = names.index(b'\0', name)
                    name = names[name:end].decode('ascii')
                    if name.startswith('descriptor_table_'):
                        self.tables[name] = value

    def read(self, address, size):
        for kind, _, offset, virtual, _, file_size, _, _ in self.segments:
            if kind == 1 and virtual <= address and address+size <= virtual+file_size:
                return self.raw[offset+address-virtual:offset+address-virtual+size]
        raise ValueError('descriptor range is not in a file-backed LOAD segment')

    def descriptors(self):
        result = {}
        for symbol, table in self.tables.items():
            pointer = self.relative.get(table+8)
            if pointer is None:
                continue
            size = struct.unpack('<I', self.read(table+24, 4))[0]
            if not 1 <= size <= 1024*1024:
                raise ValueError('invalid generated descriptor length')
            raw = self.read(pointer, size)
            desc = descriptor_pb2.FileDescriptorProto()
            desc.ParseFromString(raw)
            path = PurePosixPath(desc.name)
            if (not desc.name.endswith('.proto') or path.is_absolute()
                    or '..' in path.parts or '\\' in desc.name):
                raise ValueError('invalid descriptor filename')
            if desc.name in result:
                raise ValueError('duplicate descriptor filename')
            result[desc.name] = (desc, raw, symbol, table, pointer)
        return result


def options(value):
    parts = []
    for field, item in value.ListFields():
        if field.type == field.TYPE_ENUM:
            item = field.enum_type.values_by_number[item].name
        elif field.type == field.TYPE_BOOL:
            item = str(item).lower()
        elif field.type == field.TYPE_STRING:
            item = json.dumps(item)
        else:
            raise ValueError('unsupported descriptor option: '+field.full_name)
        parts.append(field.name+' = '+item)
    return parts


def enum_source(enum, indent):
    lines = [indent+'enum '+enum.name+' {']
    for option in options(enum.options):
        lines.append(indent+'  option '+option+';')
    for value in enum.value:
        opts = options(value.options)
        lines.append(indent+'  '+value.name+' = '+str(value.number)
                     + (' ['+', '.join(opts)+']' if opts else '')+';')
    lines.append(indent+'}')
    return lines


def field_source(field, indent, oneof=False):
    scalar = descriptor_pb2.FieldDescriptorProto.Type.Name(field.type)[5:].lower()
    kind = field.type_name if field.type in (field.TYPE_MESSAGE, field.TYPE_ENUM) else scalar
    label = '' if oneof else {1: 'optional ', 2: 'required ', 3: 'repeated '}[field.label]
    opts = options(field.options)
    if field.HasField('default_value'):
        if field.type == field.TYPE_STRING:
            default = json.dumps(field.default_value)
        elif field.type == field.TYPE_BYTES:
            # Preserve descriptor's C-escaped bytes; don't escape them twice.
            default = '"'+field.default_value+'"'
        else:
            default = field.default_value
        opts.insert(0, 'default = '+default)
    return (indent+label+kind+' '+field.name+' = '+str(field.number)
            + (' ['+', '.join(opts)+']' if opts else '')+';')


def message_source(message, indent=''):
    if message.extension or message.extension_range or message.reserved_range or message.reserved_name:
        raise ValueError('unsupported message extension/reserved declaration')
    lines = [indent+'message '+message.name+' {']
    for option in options(message.options):
        lines.append(indent+'  option '+option+';')
    for enum in message.enum_type:
        lines.extend(enum_source(enum, indent+'  '))
    for nested in message.nested_type:
        lines.extend(message_source(nested, indent+'  '))
    for field in message.field:
        if not field.HasField('oneof_index'):
            lines.append(field_source(field, indent+'  '))
    for index, oneof in enumerate(message.oneof_decl):
        lines.append(indent+'  oneof '+oneof.name+' {')
        for field in message.field:
            if field.HasField('oneof_index') and field.oneof_index == index:
                lines.append(field_source(field, indent+'    ', oneof=True))
        lines.append(indent+'  }')
    lines.append(indent+'}')
    return lines


def proto_source(desc):
    if desc.service or desc.extension or desc.syntax not in ('', 'proto2'):
        raise ValueError('unsupported file descriptor feature')
    lines = ['// Reconstructed from the fixed Steam Link Android 1.3.32 ELF.',
             '// Field/schema facts for interoperability; generated by tools/steam-remote-descriptors.py.',
             'syntax = "proto2";']
    if desc.package:
        lines.append('package '+desc.package+';')
    for dependency in desc.dependency:
        lines.append('import '+json.dumps(dependency)+';')
    for option in options(desc.options):
        lines.append('option '+option+';')
    for enum in desc.enum_type:
        lines.extend(['']+enum_source(enum, ''))
    for message in desc.message_type:
        lines.extend(['']+message_source(message))
    return '\n'.join(lines)+'\n'


def extract(elf_path, output):
    elf = SampleELF(elf_path.read_bytes())
    available = elf.descriptors()
    selected = {}

    def add(name):
        if name in selected:
            return
        selected[name] = available[name]
        for dependency in available[name][0].dependency:
            add(dependency)
    for root in ROOTS:
        add(root)
    # Render and validate everything before creating output.
    if any(Path(name).name != name for name in selected):
        raise ValueError('selected schemas must have flat filenames')
    rendered = {name: proto_source(item[0]) for name, item in selected.items()}
    output.mkdir(parents=True, exist_ok=False)
    fds = descriptor_pb2.FileDescriptorSet()
    manifest = {'sample_sha256': SAMPLE_SHA256, 'files': []}
    for name, (desc, raw, symbol, table, pointer) in selected.items():
        (output/name).write_text(rendered[name])
        (output/(name+'.desc')).write_bytes(raw)
        fds.file.add().CopyFrom(desc)
        manifest['files'].append({'name': name, 'symbol': symbol, 'table_va': hex(table),
                                 'descriptor_va': hex(pointer), 'bytes': len(raw),
                                 'sha256': hashlib.sha256(raw).hexdigest(),
                                 'dependencies': list(desc.dependency)})
    (output/'steamlink.protoset').write_bytes(fds.SerializeToString())
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return len(selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    count = extract(args.elf, args.output)
    print(json.dumps({'schemas': count, 'output': str(args.output), 'sample_sha256': SAMPLE_SHA256}))


if __name__ == '__main__':
    main()
