"""Offline inspection and extraction of supported installer containers."""
from __future__ import annotations

import re
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class UnpackError(Exception):
    """The input is unsupported, incomplete, or could not be extracted."""


@dataclass(frozen=True)
class Segment:
    name: str
    offset: int
    size: int


def detect(path: Path) -> str:
    with path.open('rb') as f:
        head = f.read(131072)
    if head.startswith(b'#!') and b'InstallAnywhere' in head:
        return 'installanywhere-unix'
    if head.startswith(b'ISc('):
        return 'installshield-cabinet'
    if head.startswith(b'MZ'):
        # PE version resources may be UTF-16LE. These are hints, not proof of
        # a supported archive layout; extraction validates via its backend.
        with path.open('rb') as f:
            carry = b''
            while chunk := f.read(1024 * 1024):
                data = carry + chunk
                if any(s in data for s in (b'InstallShield', 'InstallShield'.encode('utf-16le'), b'ISInternalVersion', 'ISInternalVersion'.encode('utf-16le'))):
                    return 'installshield-exe'
                carry = data[-64:]
        return 'unknown-pe'
    return 'unknown'


def ia_segments(path: Path) -> list[Segment]:
    with path.open('rb') as f:
        header = f.read(131072)
    if not header.startswith(b'#!') or b'InstallAnywhere' not in header:
        raise UnpackError('Unrecognized InstallAnywhere Unix header.')
    values = {}
    for key, value in re.findall(rb'(?m)^(BLOCKSIZE|JRESTART|JREREALSIZE|ARCHSTART|ARCHREALSIZE|RESSIZE|RESREALSIZE)=([0-9]+)\r?$', header):
        k = key.decode('ascii')
        if k in values:
            raise UnpackError(f'Duplicate header value: {k}.')
        values[k] = int(value)
    try:
        block = values['BLOCKSIZE']
        archive_size = values['ARCHREALSIZE']
        if block <= 0 or archive_size <= 0:
            raise ValueError
        segments = []
        if 'JRESTART' in values:
            jre_size = values['JREREALSIZE']
            if jre_size <= 0:
                raise ValueError
            jre_offset = values['JRESTART'] * block
            segments.append(Segment('jre.archive', jre_offset, jre_size))
            archive_offset = jre_offset + ((jre_size + block - 1) // block) * block
        else:
            archive_offset = values['ARCHSTART'] * block
        segments.append(Segment('install.zip', archive_offset, archive_size))
        if 'RESSIZE' in values and values['RESSIZE']:
            resource_size = values['RESREALSIZE']
            if resource_size <= 0 or resource_size > values['RESSIZE'] * block:
                raise ValueError
            resource_offset = archive_offset + ((archive_size + block - 1) // block) * block
            segments.append(Segment('Resource1.zip', resource_offset, resource_size))
    except (KeyError, ValueError) as exc:
        raise UnpackError('Missing header field or invalid archive size.') from exc
    file_size = path.stat().st_size
    previous_end = 0
    for segment in segments:
        if segment.offset < previous_end or segment.offset + segment.size > file_size:
            raise UnpackError(f'Segment {segment.name} is outside the file or overlaps another segment.')
        previous_end = segment.offset + segment.size
    return segments


def copy_segment(source: Path, segment: Segment, dest: Path) -> None:
    with source.open('rb') as inp, dest.open('xb') as out:
        inp.seek(segment.offset)
        remaining = segment.size
        while remaining:
            data = inp.read(min(1024 * 1024, remaining))
            if not data:
                raise UnpackError(f'Segment {segment.name} is truncated.')
            out.write(data)
            remaining -= len(data)


def extract_zip(source: Path, dest: Path) -> None:
    try:
        archive = zipfile.ZipFile(source)
    except zipfile.BadZipFile as exc:
        # Some InstallAnywhere ZIPs contain malformed nonessential extra fields.
        # 7-Zip can read those; verify the entire archive before extraction.
        if not str(exc).startswith('Corrupt extra field'):
            raise UnpackError(f'Cannot open ZIP {source.name}: {exc}') from exc
        extract_zip_7z(source, dest)
        return
    try:
        with archive:
            seen = set()
            for item in archive.infolist():
                name = item.filename.replace('\\', '/')
                parts = PurePosixPath(name).parts
                if (not parts or name.startswith('/') or '..' in parts or ':' in parts[0]
                        or stat.S_ISLNK(item.external_attr >> 16)):
                    raise UnpackError(f'Unsafe ZIP path: {item.filename!r}')
                relative = Path(*parts)
                if relative in seen:
                    raise UnpackError(f'Duplicate ZIP path: {item.filename!r}')
                seen.add(relative)
                target = dest / relative
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as inp, target.open('xb') as out:
                        shutil.copyfileobj(inp, out, 1024 * 1024)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise UnpackError(f'Cannot extract ZIP {source.name}: {exc}') from exc


def extract_zip_7z(source: Path, dest: Path, archive_type: str = "zip") -> None:
    command = require_tool('7z')
    # Exit 1 can mean a warning (including malformed extra fields), so require
    # the tool's explicit success marker for both test and extraction.
    for operation in ('t', 'x'):
        args = [command, operation, f'-t{archive_type}', '-y', '-bd', '-bso1', '-bse1']
        if operation == 'x':
            args.append(f'-o{dest}')
        args.extend(['--', str(source)])
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
        if result.returncode not in (0, 1) or 'Everything is Ok' not in result.stdout:
            raise UnpackError(f'7z {operation} failed for {source.name}:\n{result.stdout[-2000:]}')
        if result.returncode == 1:
            print(f'7z: {source.name} has metadata warnings; data verification passed.')


def unpack_ia(source: Path, dest: Path, archives_only: bool = False) -> None:
    segments = ia_segments(source)
    archive_dir = dest / 'archives'
    archive_dir.mkdir()
    for segment in segments:
        out = archive_dir / segment.name
        print(f'Extracting {segment.name}: offset={segment.offset}, bytes={segment.size}')
        copy_segment(source, segment, out)
        if not archives_only and segment.name.endswith('.zip'):
            extract_zip(out, dest / segment.name.removesuffix('.zip'))


def require_tool(name: str) -> str:
    command = shutil.which(name)
    if not command:
        raise UnpackError(f'Missing tool {name} in PATH; see README.md.')
    return command


def run_tool(args: list[str], cwd: Path) -> None:
    result = subprocess.run(args, cwd=cwd, check=False)
    if result.returncode:
        raise UnpackError(f'{Path(args[0]).name} failed (exit {result.returncode}).')


def unpack_shield(source: Path, dest: Path, kind: str, archives_only: bool = False) -> None:
    if kind == 'installshield-cabinet':
        unshield = require_tool('unshield')
        run_tool([unshield, '-d', str(dest / 'files'), 'x', str(source)], dest)
        return
    from .shield import extract_setup
    raw = dest / 'setup-files'
    extract_setup(source, raw)
    if archives_only:
        return
    cabinets = sorted(p for p in raw.rglob('*') if p.name.lower() == 'data1.cab')
    if not cabinets:
        raise UnpackError('Setup files extracted but data1.cab is missing; use --archives-only to request setup files only.')
    unshield = require_tool('unshield')
    for index, cabinet in enumerate(cabinets):
        output = dest / ('files' if len(cabinets) == 1 else f'files-{index + 1}')
        run_tool([unshield, '-d', str(output), 'x', str(cabinet)], dest)


def extract_payloads(dest: Path) -> int:
    """Expand IA data JARs and 7-Zip SFX payloads, retaining original files."""
    candidates = []
    for base in (dest / 'Resource1', dest / 'install', dest / 'files'):
        if not base.exists():
            continue
        for path in sorted(base.rglob('*')):
            if not path.is_file():
                continue
            if path.name.endswith('_zg_ia_sf.jar'):
                candidates.append((path, 'zip'))
            elif path.suffix.lower() == '.exe':
                with path.open('rb') as stream:
                    header = stream.read(1024 * 1024)
                if header.startswith(b'MZ') and b'7z\xbc\xaf\x27\x1c' in header:
                    candidates.append((path, '7z'))
    for path, kind in candidates:
        out = dest / 'payloads' / path.relative_to(dest)
        out = out.with_name(out.name + '.unpacked')
        print(f'Expanding payload: {path.relative_to(dest)}', flush=True)
        if kind == 'zip':
            extract_zip(path, out)
        else:
            extract_zip_7z(path, out, '7z')
    return len(candidates)
