"""Explicit, checksum-pinned optional backend setup. Never used during extraction."""
import hashlib
import urllib.request
from pathlib import Path

from .core import UnpackError

PACK200_URL = 'https://repo.maven.apache.org/maven2/org/glavo/pack200/0.3.0/pack200-0.3.0.jar'
PACK200_SHA256 = '9b65fae9a51947f8d9bb9f2baf5eeacbddc74423037372fe3d4f62b78f30635d'


def setup_pack200():
    target = Path.home() / '.cache' / 'installerunpack' / 'pack200-0.3.0.jar'
    if target.exists():
        data = target.read_bytes()
    else:
        with urllib.request.urlopen(PACK200_URL, timeout=60) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != PACK200_SHA256:
        raise UnpackError('Pack200 library checksum mismatch; refusing to use the download or existing cache.')
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as out:
            out.write(data)
    print(f'Pack200 decoder ready: {target}')
    print('Requires JDK 11+ on PATH. Library source/license: https://github.com/Glavo/pack200')
    return 0
