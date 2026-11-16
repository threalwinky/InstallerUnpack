import struct
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from installerunpack.core import UnpackError
from installerunpack.shield import extract_setup, shield_segments


def make_pe(path, name='Disk1/data1.cab', data=b'ISc(payload', unicode=True):
    pe = bytearray(512)
    pe[:2] = b'MZ'
    struct.pack_into('<I', pe, 60, 64)
    pe[64:68] = b'PE\0\0'
    struct.pack_into('<H', pe, 70, 1)
    struct.pack_into('<H', pe, 84, 224)
    struct.pack_into('<H', pe, 88, 0x10b)
    struct.pack_into('<I', pe, 148, 512)
    struct.pack_into('<II', pe, 328, 0, 512)
    encoding = 'utf-16le' if unicode else 'cp1252'
    overlay = struct.pack('<I', 1) if unicode else b''
    overlay += ''.join(x + '\0' for x in ('data1.cab', name, '1.0.0.0', str(len(data)))).encode(encoding) + data
    path.write_bytes(pe + overlay)


class ShieldTests(unittest.TestCase):
    def test_unicode_and_ansi_tables(self):
        for unicode in (True, False):
            with self.subTest(unicode=unicode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source = root / 'setup.exe'
                make_pe(source, unicode=unicode)
                entries = shield_segments(source)
                self.assertEqual(len(entries), 1)
                extract_setup(source, root / 'out')
                self.assertEqual((root / 'out/Disk1/data1.cab').read_bytes(), b'ISc(payload')

    def test_truncated_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'setup.exe'
            make_pe(source)
            source.write_bytes(source.read_bytes()[:-1])
            with self.assertRaises(UnpackError):
                shield_segments(source)

    def test_reject_path_traversal_before_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'setup.exe'
            make_pe(source, name='../escape')
            with self.assertRaises(UnpackError):
                extract_setup(source, Path(temp) / 'out')
            self.assertFalse((Path(temp) / 'out').exists())

    def test_reject_unparsed_payload_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'setup.exe'
            make_pe(source)
            with source.open('ab') as out:
                out.write(b'unrecognized second payload')
            with self.assertRaises(UnpackError):
                shield_segments(source)
