import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from installerunpack.core import UnpackError, detect, extract_zip, ia_segments


def make_zip(name, data):
    data_file = io.BytesIO()
    with zipfile.ZipFile(data_file, 'w') as archive:
        archive.writestr(name, data)
    return data_file.getvalue()


def make_installer(path):
    block = 512
    archive = make_zip('inside.txt', 'hello')
    resource = make_zip('resource.txt', 'world')
    header = (f'#!/bin/sh\n# InstallAnywhere\nBLOCKSIZE={block}\nARCHSTART=1\n'
              f'ARCHREALSIZE={len(archive)}\nRESSIZE=1\nRESREALSIZE={len(resource)}\n').encode()
    path.write_bytes(header.ljust(block, b'\0') + archive.ljust(block, b'\0') + resource)
    return archive, resource


class InstallerTests(unittest.TestCase):
    def test_extract_unix_segments_and_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'sample.bin'
            archive, resource = make_installer(source)
            self.assertEqual(detect(source), 'installanywhere-unix')
            segments = ia_segments(source)
            self.assertEqual([(s.offset, s.size) for s in segments], [(512, len(archive)), (1024, len(resource))])
            result = subprocess.run([sys.executable, str(ROOT / 'src/main.py'), 'unpack', str(source), '-o', str(root / 'out')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'out/install/inside.txt').read_text(), 'hello')
            self.assertEqual((root / 'out/Resource1/resource.txt').read_text(), 'world')
            self.assertEqual((root / 'out/archives/install.zip').read_bytes(), archive)
            again = subprocess.run([sys.executable, str(ROOT / 'src/main.py'), 'unpack', str(source), '-o', str(root / 'out')], capture_output=True)
            self.assertNotEqual(again.returncode, 0)

    def test_truncated_installer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'sample.bin'
            make_installer(source)
            source.write_bytes(source.read_bytes()[:-1])
            with self.assertRaises(UnpackError):
                ia_segments(source)

    def test_zip_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'bad.zip'
            source.write_bytes(make_zip('../escaped', 'unsafe'))
            with self.assertRaises(UnpackError):
                extract_zip(source, root / 'out')
            self.assertFalse((root / 'escaped').exists())

    def test_installshield_header_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'data1.hdr'
            source.write_bytes(b'ISc(' + b'\0' * 30)
            self.assertEqual(detect(source), 'installshield-cabinet')


if __name__ == '__main__':
    unittest.main()
