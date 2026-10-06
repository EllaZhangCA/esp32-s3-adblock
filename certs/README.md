# TLS trust bundle

`cacert.pem` is the Mozilla public root set shipped by certifi 2026.7.22.
See LICENSE (MPL-2.0). It contains public certificates, never private keys.
`x509_crt_bundle` is its deterministic 55,587-byte ESP-IDF/Arduino bundle.

To regenerate after reviewing a trusted root-store update:

```sh
python -m pip install -r requirements-dev.txt
python tools/build_ca_bundle.py
python -m unittest discover -s test -v
```

The firmware checks server hostname, certificate chain and validity time.
NTP must synchronize before remote downloads. TLS failures retain the old list.
The bundle is vendored so ordinary builds do not download trust anchors.
