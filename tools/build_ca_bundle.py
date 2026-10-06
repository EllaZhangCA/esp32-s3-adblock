"""Build the Arduino ESP32/ESP-IDF 4.x certificate-bundle format.

Input: vendored Mozilla roots from certifi (MPL-2.0), not a network download.
Requires cryptography, installed by PlatformIO's esptool package.
"""
from pathlib import Path
import struct
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]

def build(pem: bytes) -> bytes:
    entries = {}
    for cert in x509.load_pem_x509_certificates(pem):
        subject = cert.subject.public_bytes()
        key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if subject in entries and entries[subject] != key:
            raise ValueError("Conflicting keys for the same root subject")
        entries[subject] = key
    if not entries:
        raise ValueError("Empty certificate bundle")
    result = bytearray(struct.pack('>H', len(entries)))
    for subject, key in sorted(entries.items()):
        result += struct.pack('>HH', len(subject), len(key)) + subject + key
    return bytes(result)

if __name__ == '__main__':
    result = build((ROOT / 'certs/cacert.pem').read_bytes())
    (ROOT / 'certs/x509_crt_bundle').write_bytes(result)
    print(f'CA bundle: {len(result)} bytes')
