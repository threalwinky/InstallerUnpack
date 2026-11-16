"""Recursive archive expansion, including nested JARs and Pack200 libraries."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import struct
import zlib
from collections import deque
from pathlib import Path

from .core import UnpackError, extract_zip, extract_zip_7z, require_tool
from .shield import safe_path


def has_7z_header(path):
    # Executables such as 7za.exe contain the magic as a constant without
    # containing an archive. Validate the start-header CRC and byte bounds.
    with path.open('rb') as stream:
        data = stream.read(1024 * 1024)
    offset = 0
    size = path.stat().st_size
    while True:
        offset = data.find(b'7z\xbc\xaf\x27\x1c', offset)
        if offset < 0:
            return False
        header = data[offset:offset + 32]
        if len(header) == 32:
            crc = struct.unpack_from('<I', header, 8)[0]
            next_offset, next_size = struct.unpack_from('<QQ', header, 12)
            if zlib.crc32(header[12:]) == crc and offset + 32 + next_offset + next_size <= size:
                return True
        offset += 1


def archive_kind(path):
    with path.open('rb') as stream:
        head = stream.read(1024)
    if head.startswith(b'PK\x03\x04') or head.startswith(b'PK\x05\x06'):
        return 'zip'
    if head.startswith(b'\xca\xfe\xd0\x0d'):
        return 'pack200'
    if head.startswith(b'\x1f\x8b'):
        with gzip.open(path, 'rb') as stream:
            inner = stream.read(512)
        return 'pack200' if inner.startswith(b'\xca\xfe\xd0\x0d') else 'tar' if inner[257:262] == b'ustar' else 'gzip'
    if head[257:262] == b'ustar':
        return 'tar'
    if (head.startswith(b'7z\xbc\xaf\x27\x1c') or head.startswith(b'MZ')) and has_7z_header(path):
        return '7z'
    if path.suffix.lower() in ('.jar', '.war', '.ear', '.zip', '.pack', '.gz', '.7z'):
        return 'unsupported'
    return None


def unpack_packs(pairs, library=None, unpack200=None):
    executable = unpack200 or shutil.which('unpack200')
    if executable:
        for source, target in pairs:
            result = subprocess.run([str(executable), str(source), str(target)], capture_output=True, text=True)
            if result.returncode:
                raise UnpackError(result.stderr[-1000:] or f'unpack200 failed: {source}')
        return
    library = library or os.environ.get('INSTALLERUNPACK_PACK200_JAR') or Path.home() / '.cache' / 'installerunpack' / 'pack200-0.3.0.jar'
    if not library or not Path(library).is_file():
        raise UnpackError('Reading .pack.gz requires unpack200 in PATH or --pack200-jar /path/to/pack200-0.3.0.jar.')
    bridge = Path(__file__).parent / 'resources' / 'Unpack200.java'
    with tempfile.TemporaryDirectory(prefix='installerunpack-pack200-') as temp:
        manifest = Path(temp) / 'files.txt'
        manifest.write_text(''.join(base64.b64encode(str(p).encode()).decode() + '\n' for pair in pairs for p in pair), encoding='utf-8')
        result = subprocess.run([require_tool('java'), '--class-path', str(Path(library).resolve()), str(bridge), str(manifest)], capture_output=True, text=True)
        if result.returncode:
            raise UnpackError(f'Pack200 decoder failed: {result.stderr[-2000:]}')
        if result.stderr:
            print(result.stderr[-2000:])


def extract_tar(source, dest):
    dest.mkdir()
    with tarfile.open(source, 'r:*') as archive:
        links = []
        for member in archive:
            name = member.name
            if name in ('.', './'):
                continue
            target = dest / str(safe_path(name))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out)
            elif member.issym() or member.islnk():
                links.append((member, target))
            else:
                raise UnpackError(f'Unsupported TAR entry: {name}')
        # Create links only after all regular files, so writes cannot follow a
        # link supplied by the archive. Never scan linked directories.
        for member, target in links:
            link = member.linkname
            linked = target.parent / link if member.issym() else dest / link
            if not linked.resolve().is_relative_to(dest.resolve()):
                raise UnpackError(f'TAR link points outside the output: {member.name}')
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                target.symlink_to(link)
            else:
                os.link(linked, target)


def expand_tree(dest, max_depth=16, max_archives=10000, pack200_jar=None, unpack200=None):
    """Expand each unique archive once; report duplicates and every failure."""
    roots = [p for p in dest.iterdir() if p.is_dir() and p.name not in ('archives', 'setup-files', 'payloads')]
    queue = deque((p, 0) for root in sorted(roots) for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink())
    jre = dest / 'archives' / 'jre.archive'
    if jre.exists():
        queue.append((jre, 0))
    records, seen = [], {}
    while queue:
        packs = []
        while queue:
            source, depth = queue.popleft()
            record = {'source': str(source.relative_to(dest)), 'depth': depth}
            try:
                kind = archive_kind(source)
                if not kind:
                    continue
                record['kind'] = kind
                if source.stat().st_size == 0:
                    record.update(status='empty', note='Empty placeholder in the original installer; no data to expand.')
                    records.append(record)
                    continue
                if depth >= max_depth or len(records) + len(packs) >= max_archives:
                    raise UnpackError('Archive depth/count limit reached; extraction is incomplete.')
                digest = hashlib.sha256()
                with source.open('rb') as inp:
                    for chunk in iter(lambda: inp.read(1024 * 1024), b''):
                        digest.update(chunk)
                key = digest.hexdigest()
                if key in seen:
                    record.update(status='duplicate', duplicate_of=seen[key])
                    records.append(record)
                    continue
                out = source.with_name(source.name + '.contents')
                record['output'] = str(out.relative_to(dest))
                print(f'Expanding archive: {record["source"]}', flush=True)
                if kind == 'pack200':
                    out.mkdir()
                    jar = out / (source.name.removesuffix('.gz').removesuffix('.pack') + '.jar')
                    packs.append((source, jar, depth, record, key))
                    continue
                if kind == 'zip':
                    extract_zip(source, out)
                elif kind == '7z':
                    extract_zip_7z(source, out, '7z')
                elif kind == 'tar':
                    extract_tar(source, out)
                elif kind == 'gzip':
                    out.mkdir()
                    with gzip.open(source, 'rb') as inp, (out / 'data').open('xb') as output:
                        shutil.copyfileobj(inp, output)
                else:
                    raise UnpackError('Unsupported archive signature or damaged archive.')
                record['status'] = 'extracted'
                seen[key] = record['output']
                queue.extend((p, depth + 1) for p in sorted(out.rglob('*')) if p.is_file() and not p.is_symlink())
            except (UnpackError, OSError, ValueError, tarfile.TarError, EOFError) as exc:
                record.update(status='failed', error=str(exc))
            records.append(record)
        if packs:
            error = None
            try:
                unpack_packs([(p[0], p[1]) for p in packs], pack200_jar, unpack200)
            except (UnpackError, OSError) as exc:
                error = str(exc)
            for source, jar, depth, record, key in packs:
                if jar.is_file() and jar.stat().st_size:
                    record['status'] = 'extracted'
                    seen[key] = record['output']
                    queue.append((jar, depth + 1))
                else:
                    record.update(status='failed', error=error or 'Pack200 decoder did not produce a JAR.')
                records.append(record)
    failures = sum(r['status'] == 'failed' for r in records)
    report = {'complete': not failures, 'archives': records, 'failed': failures,
              'extracted': sum(r['status'] == 'extracted' for r in records),
              'empty_placeholders': sum(r['status'] == 'empty' for r in records),
              'duplicates': sum(r['status'] == 'duplicate' for r in records)}
    (dest / 'extraction-report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    if failures:
        raise UnpackError(f'{failures} archives could not be expanded; see {dest / "extraction-report.json"}')
    return report
