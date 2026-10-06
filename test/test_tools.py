import configparser
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('blocklist', ROOT/'tools/build_blocklist.py')
bl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bl)

class BlocklistTests(unittest.TestCase):
    def run_builder(self, source, *extra):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d); (path/'in.txt').write_text(source, encoding='utf-8')
            (path/'out.bin').write_bytes(b'original')
            p = subprocess.run([sys.executable, str(ROOT/'tools/build_blocklist.py'),
                                str(path/'out.bin'), str(path/'in.txt'), *extra], capture_output=True)
            return p.returncode, (path/'out.bin').read_bytes()

    def test_mixed_formats_allow_and_duplicates(self):
        code, blob = self.run_builder('||ads.example.com^\n@@||ok.example.org^\n||ok.example.org^\n'
                                     '0.0.0.0 hosts.example.com alias.example.com\nPLAIN.EXAMPLE.COM.\n'
                                     'plain.example.com\n||ignore.example.com^$third-party\n/^regex$/\n')
        expected = sorted(bl.fnv(d.encode()) for d in ['ads.example.com','hosts.example.com','alias.example.com','plain.example.com'])
        self.assertEqual(code, 0)
        self.assertEqual(blob, b''.join(h.to_bytes(5,'little') for h in expected))

    def test_www_does_not_overblock_parent(self):
        code, blob = self.run_builder('www.example.com\n')
        self.assertEqual(code, 0)
        self.assertEqual(blob, bl.fnv(b'www.example.com').to_bytes(5,'little'))

    def test_invalid_input_preserves_previous_file(self):
        code, blob = self.run_builder('0.0.0.0 localhost\n<script>.com\na..com\n*.example.com\n127.0.0.1\n')
        self.assertNotEqual(code, 0); self.assertEqual(blob, b'original')

    def test_missing_source_preserves_previous_file(self):
        code, blob = self.run_builder('valid.example\n', 'definitely-not-a-real-file')
        self.assertNotEqual(code, 0); self.assertEqual(blob, b'original')

    def test_fnv_known_vector(self):
        self.assertEqual(bl.fnv(b'hello'), 0x4680aabd0b)

    def test_domain_limits(self):
        self.assertTrue(bl.valid_domain('a'*63+'.example'))
        self.assertFalse(bl.valid_domain('a'*64+'.example'))
        for bad in ['a..b','-a.com','a-.com','a.\x00com','https://foo.com']:
            self.assertFalse(bl.valid_domain(bad))

class ConfigurationTests(unittest.TestCase):
    def test_partition_alignment_capacity_and_ota(self):
        for mb in [4,8,16]:
            with self.subTest(mb=mb):
                rows = [line.split(',') for line in (ROOT/f'partitions/s3-{mb}mb.csv').read_text().splitlines() if line and not line.startswith('#')]
                entries = {r[0].strip(): tuple(x.strip() for x in r[1:]) for r in rows}
                end = 0x9000
                for name, (kind, subtype, offset, size) in entries.items():
                    offset, size = int(offset,0), int(size,0)
                    self.assertGreaterEqual(offset,end); self.assertEqual(offset%4096,0)
                    if kind == 'app': self.assertEqual(offset%65536,0)
                    end=offset+size
                self.assertEqual(end, mb*1024*1024)
                self.assertEqual(entries['app0'][3], entries['app1'][3])
                self.assertEqual(entries['app0'][1], 'ota_0'); self.assertEqual(entries['app1'][1], 'ota_1')
                # At least two copies of a 550 KB list plus filesystem overhead.
                self.assertGreater(int(entries['spiffs'][3],0), 2*550000+32768)

    def test_bundle_matches_reviewed_pem(self):
        spec=importlib.util.spec_from_file_location('ca',ROOT/'tools/build_ca_bundle.py')
        ca=importlib.util.module_from_spec(spec); spec.loader.exec_module(ca)
        self.assertEqual(ca.build((ROOT/'certs/cacert.pem').read_bytes()), (ROOT/'certs/x509_crt_bundle').read_bytes())

if __name__ == '__main__':
    unittest.main()
