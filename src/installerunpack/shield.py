"""Read InstallShield ANSI/UTF-16 file tables without executing the PE.

Format references: hifi/iss_extract and pawstas80/Unpacker (see README).
This is an independent reader with explicit bounds and output path validation.
"""
import re
import struct
from pathlib import PurePosixPath

from .core import Segment, UnpackError, copy_segment


def safe_path(name):
    name = name.replace('\\', '/')
    parts = PurePosixPath(name).parts
    if not parts or name.startswith('/') or any(p in ('.', '..') or ':' in p for p in parts):
        raise UnpackError(f'Unsafe archive path: {name!r}')
    return PurePosixPath(*parts)


def overlay_bounds(path):
    size = path.stat().st_size
    with path.open('rb') as f:
        def read_at(offset, length):
            if offset < 0 or offset + length > size:
                raise UnpackError('Truncated PE file.')
            f.seek(offset)
            return f.read(length)
        if read_at(0, 2) != b'MZ':
            raise UnpackError('Not a PE file.')
        pe = struct.unpack('<I', read_at(60, 4))[0]
        header = read_at(pe, 24)
        if header[:4] != b'PE\0\0':
            raise UnpackError('Invalid PE signature.')
        count = struct.unpack_from('<H', header, 6)[0]
        optional_size = struct.unpack_from('<H', header, 20)[0]
        if not 1 <= count <= 96 or optional_size < 64:
            raise UnpackError('Invalid PE section table.')
        optional = read_at(pe + 24, optional_size)
        magic = struct.unpack_from('<H', optional)[0]
        if magic not in (0x10b, 0x20b):
            raise UnpackError('Unsupported PE optional header.')
        start = struct.unpack_from('<I', optional, 60)[0]
        for i in range(count):
            section = read_at(pe + 24 + optional_size + i * 40, 40)
            length, offset = struct.unpack_from('<II', section, 16)
            if length:
                read_at(offset + length - 1, 1)
                start = max(start, offset + length)
        end = size
        # The security directory contains file offsets, not RVAs.
        directory = 96 if magic == 0x10b else 112
        if len(optional) >= directory + 40:
            cert, cert_size = struct.unpack_from('<II', optional, directory + 32)
            if cert_size:
                if cert < start or cert + cert_size > size:
                    raise UnpackError('PE certificate table is outside the file.')
                end = cert
        if start >= end:
            raise UnpackError('PE has no payload overlay.')
        return start, end


def shield_segments(path):
    start, end = overlay_bounds(path)
    with path.open('rb') as f:
        f.seek(start)
        prefix = f.read(4)
        count = struct.unpack('<I', prefix)[0]
        unicode_table = 0 < count <= min(100000, (end - start - 4) // 10)
        f.seek(start + 4 if unicode_table else start)
        width = 2 if unicode_table else 1

        def string(limit):
            data = bytearray()
            for _ in range(limit):
                if f.tell() + width > end:
                    break
                unit = f.read(width)
                if unit == b'\0' * width:
                    try:
                        return data.decode('utf-16le' if unicode_table else 'cp1252')
                    except UnicodeError as exc:
                        raise UnpackError('Invalid InstallShield filename encoding.') from exc
                data.extend(unit)
            raise UnpackError('InstallShield metadata string is too long or unterminated.')

        entries = []
        seen = set()
        for _ in range(count if unicode_table else 100000):
            if not unicode_table and (f.tell() >= end or entries and f.tell() + 8 >= end):
                break
            name, full, version, length = string(4096), string(4096), string(512), string(32)
            if not re.fullmatch(r'[0-9]+', length):
                raise UnpackError('Invalid InstallShield entry size; unsupported layout.')
            relative = safe_path(full or name)
            key = str(relative).casefold()
            if key in seen:
                raise UnpackError(f'Duplicate InstallShield entry: {relative}')
            seen.add(key)
            length = int(length)
            offset = f.tell()
            if offset + length > end:
                raise UnpackError(f'Entry {relative} extends beyond the PE payload.')
            entries.append(Segment(str(relative), offset, length))
            f.seek(offset + length)
            if not unicode_table and f.tell() == end:
                break
        if not entries:
            raise UnpackError('No supported InstallShield file table found.')
        # Never silently drop a second payload appended after a counted table.
        tail = f.read(min(8, end - f.tell()))
        if any(tail) or f.tell() < end:
            raise UnpackError('Unparsed data follows the InstallShield table; additional layout is unsupported.')
        return entries


def extract_setup(source, dest):
    entries = shield_segments(source)
    dest.mkdir()
    for entry in entries:
        target = dest / entry.name
        target.parent.mkdir(parents=True, exist_ok=True)
        print(f'Extracting {entry.name}: bytes={entry.size}', flush=True)
        copy_segment(source, entry, target)
    return entries
