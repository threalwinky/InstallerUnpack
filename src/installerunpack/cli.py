#!/usr/bin/env python3
"""Inspect and unpack supported InstallAnywhere and InstallShield files."""
import argparse
import sys
from pathlib import Path

from .core import UnpackError, detect, ia_segments, unpack_ia, unpack_shield, extract_payloads


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspect and extract supported InstallAnywhere / InstallShield installers offline.')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('setup-pack200', help='Download and verify the optional Pack200 decoder (one-time network setup)')
    inspect = sub.add_parser('inspect', help='Identify an installer and list embedded files')
    inspect.add_argument('installer', type=Path)
    unpack = sub.add_parser('unpack', help='Extract into a new directory')
    unpack.add_argument('installer', type=Path)
    unpack.add_argument('-o', '--output', required=True, type=Path, help='Output directory (must not exist)')
    unpack.add_argument('--archives-only', action='store_true', help='Carve archives and metadata without expanding ZIP or CAB files')
    unpack.add_argument('--extract-payloads', action='store_true', help='Legacy payload extraction when --no-recursive is used')
    unpack.add_argument('--recursive', action=argparse.BooleanOptionalAction, default=True, help='Expand nested JAR/ZIP, Pack200, TAR, gzip and 7-Zip archives (default: enabled)')
    unpack.add_argument('--max-depth', type=int, default=16, help='Maximum archive depth (default: 16)')
    unpack.add_argument('--max-archives', type=int, default=10000, help='Maximum archive count (default: 10000)')
    unpack.add_argument('--pack200-jar', type=Path, help='Glavo Pack200 library for decoding .pack.gz using JDK >= 11')
    unpack.add_argument('--unpack200', type=Path, help='Optional unpack200 executable from JDK 8-13')
    args = parser.parse_args(argv)
    if args.command == 'unpack' and (args.max_depth < 1 or args.max_archives < 1):
        parser.error('Archive limits must be positive')
    if args.command == 'unpack' and args.archives_only and args.extract_payloads:
        parser.error('--archives-only cannot be combined with --extract-payloads')
    try:
        if args.command == 'setup-pack200':
            from .backends import setup_pack200
            return setup_pack200()
        source = args.installer.resolve(strict=True)
        if not source.is_file():
            raise UnpackError('Input must be a file.')
        kind = detect(source)
        print(f'Format: {kind}')
        if args.command == 'inspect':
            if kind == 'installanywhere-unix':
                for segment in ia_segments(source):
                    print(f'{segment.name}: offset={segment.offset}, bytes={segment.size}')
            elif kind == 'installshield-exe':
                from .shield import shield_segments
                for segment in shield_segments(source):
                    print(f'{segment.name}: offset={segment.offset}, bytes={segment.size}')
            return 0 if kind not in ('unknown', 'unknown-pe') else 1
        if kind not in ('installanywhere-unix', 'installshield-cabinet', 'installshield-exe'):
            raise UnpackError('Unsupported or unrecognized installer format.')
        if args.archives_only and kind not in ('installanywhere-unix', 'installshield-exe'):
            raise UnpackError('--archives-only requires an installer with embedded archives.')
        dest = args.output.resolve()
        dest.mkdir(parents=True, exist_ok=False)
        if kind == 'installanywhere-unix':
            unpack_ia(source, dest, args.archives_only)
        else:
            unpack_shield(source, dest, kind, args.archives_only)
        if args.recursive and not args.archives_only:
            from .recursive import expand_tree
            report = expand_tree(dest, args.max_depth, args.max_archives, args.pack200_jar, args.unpack200)
            print(f'Expanded {report["extracted"]} nested archives; {report["duplicates"]} duplicates referenced in the report.')
        elif args.extract_payloads:
            count = extract_payloads(dest)
            print(f'Extracted {count} additional payloads.')
        print(f'Completed: {dest}')
        return 0
    except (UnpackError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
