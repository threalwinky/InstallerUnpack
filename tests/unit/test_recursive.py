import gzip
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from installerunpack.core import UnpackError
from installerunpack.recursive import expand_tree, archive_kind


def jar_bytes(name, content):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as jar:
        jar.writestr(name, content)
    return stream.getvalue()


class RecursiveTests(unittest.TestCase):
    def test_nested_jar_preserves_archives_and_extracts_resources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lib = root / 'files/lib'
            lib.mkdir(parents=True)
            inner = jar_bytes('config.properties', b'key=value')
            outer = jar_bytes('lib/inner.jar', inner)
            (lib / 'outer.jar').write_bytes(outer)
            report = expand_tree(root)
            self.assertTrue(report['complete'])
            self.assertEqual(report['extracted'], 2)
            self.assertEqual((lib / 'outer.jar').read_bytes(), outer)
            self.assertEqual((lib / 'outer.jar.contents/lib/inner.jar.contents/config.properties').read_bytes(), b'key=value')

    def test_gzip_wrapped_jar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'files').mkdir()
            source = root / 'files/archive.gz'
            source.write_bytes(gzip.compress(jar_bytes('hello.txt', b'hello')))
            self.assertTrue(expand_tree(root)['complete'])
            self.assertEqual((root / 'files/archive.gz.contents/data.contents/hello.txt').read_bytes(), b'hello')

    def test_duplicate_report_points_to_existing_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'files').mkdir()
            data = jar_bytes('file.txt', b'data')
            for name in ('a.jar', 'b.jar'):
                (root / 'files' / name).write_bytes(data)
            report = expand_tree(root)
            duplicate = next(r for r in report['archives'] if r['status'] == 'duplicate')
            self.assertTrue((root / duplicate['duplicate_of'] / 'file.txt').exists())

    def test_empty_placeholder_is_preserved_and_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'files').mkdir()
            source = root / 'files/empty.jar'
            source.touch()
            report = expand_tree(root)
            self.assertTrue(report['complete'])
            self.assertEqual(report['empty_placeholders'], 1)
            self.assertEqual(source.stat().st_size, 0)

    def test_executable_with_magic_constant_is_not_a_7zip_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / '7za.exe'
            source.write_bytes(b'MZ' + b'7z\xbc\xaf\x27\x1c' + b'\0' * 64)
            self.assertIsNone(archive_kind(source))

    def test_depth_limit_and_invalid_jar_are_not_reported_as_complete(self):
        for depth in (1, 16):
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'files').mkdir()
                content = jar_bytes('inner.jar', jar_bytes('file', b'x')) if depth == 1 else b'invalid'
                (root / 'files/archive.jar').write_bytes(content)
                with self.assertRaises(UnpackError):
                    expand_tree(root, max_depth=depth)
                report = json.loads((root / 'extraction-report.json').read_text())
                self.assertFalse(report['complete'])
                self.assertEqual(report['failed'], 1)
