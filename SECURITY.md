# Security policy and review

Review baseline: upstream `1947383` from M-Abozaid/esp32-c3-adblock. This is a code review and targeted test exercise, not an independent penetration test or a security certification.

## Changes

| Finding | Change | Verification |
| --- | --- | --- |
| Public placeholder administration / OTA credentials | Per-device 128-bit random passwords, generated after WiFi enables RF entropy, persisted in NVS; printed only to the physical serial console | Source review, all firmware builds |
| Open provisioning AP exposes WiFi credentials over radio | WPA2 AP with separate random password; per-boot form token | Build/source checks; hardware radio test pending |
| SSID injected into HTML and wrong escaping of option attributes | Escape HTML text and attributes; validate WiFi length | Source review; hardware browser test pending |
| Remote list fetch used `setInsecure()` and accepted HTTP | Vendored Mozilla trust bundle, hostname/chain/time validation, HTTPS-only redirect validation, bounded hops/time/size | Bundle reproducibility test, source review; on-device TLS test pending |
| Failed or truncated list upload deleted working list | Stage separately, reject partial writes, validate sorted unique entries, retain backup across renames | C++ storage fault/recovery tests; real power-cut test pending |
| Oversized/malformed DNS datagrams were partially processed | Reject truncation, multi-question/non-query/compressed/malformed inputs, require IN class, validate upstream source/ID/question/response | 100,000 generated malformed packets; CI ASan/UBSan |
| Custom rules failed without a main list | Evaluate custom hashes independently of Flash-list length | Source review/build |
| Larger S3 lists exceeded fixed 256-hash bucket | Bounded binary search for large buckets | First/last/missing entries up to 2.4M hashes |
| Read-only dashboard exposed client information | Require login for dashboard and JSON, no-store, no framing | Source review/build |
| Mutating routes used GET | POST plus same-origin custom header; uploads check auth before writing | Source review/build; live endpoint tests pending |
| List input stripped www and could broaden exact block rules | Preserve exact domain; parent suffix rules still apply | Python regression test |
| Ban persistence depended on which clients had reappeared since reboot | Independent persisted ban list, applied even with a full stats table | Source review/build |
| Stale C3 installer binaries could be flashed accidentally | Source-only S3 repository with fresh generated artifacts | Git index review and actual S3 image-header checks |

## Trust boundaries and remaining limitations

- HTTP on port 80 is not encrypted. A network observer or active LAN attacker can steal Basic Auth credentials or tamper with administration/OTA traffic. Use a trusted management LAN/VLAN; do not expose ports 53, 80 or OTA to the internet. CSRF protection is not protection against a network attacker.
- Setup WPA2 credentials and web credentials are independent and unique by default. NVS and Flash are not encrypted; physical serial/Flash access reveals passwords. A serial terminal can print them with `?`. Supplying static credentials in a local secrets.h overrides random generation; never redistribute such firmware.
- Firmware OTA uses ESP image validation, not a publisher signature. An authenticated administrator can install arbitrary compatible firmware. Secure Boot and Flash Encryption are not enabled. Network ArduinoOTA is off by default.
- Plain UDP upstream DNS is not authenticated or encrypted and the device does not validate DNSSEC. Random source ports and transaction IDs plus matching source/question reduce reply confusion; they do not stop an on-path attacker. DNS is limited to the same IPv4 subnet and has no TCP fallback.
- Hash truncation causes probabilistic collisions. Blocklist data is not cryptographically authenticated separately from HTTPS. A trusted source can still publish an incorrect or malicious list. Pin/supply your own reviewed source if needed.
- Source and dependency versions are pinned for repeatable builds. The PlatformIO Arduino core is 2.0.17-based; pinning does not prove the absence of dependency vulnerabilities. Review upstream security updates before internet-adjacent or high-assurance deployment. The certificate bundle must also be kept current.
- A malformed stored list is rejected. An absent list forwards DNS while custom rules still work. Check the dashboard's domain count; do not treat a running DNS server as proof that a production list is loaded.
- A single cooperative loop and finite RAM limit performance. HTTPS handshakes, flash work and uploads can delay DNS. Upstream timeouts are bounded; public/hostile multi-tenant networks and high-volume use are outside this design.

## Reporting

Use GitHub private vulnerability reporting if available on this repository. Otherwise open an issue with a minimal description and ask for a private disclosure channel; do not include credentials, private WiFi information or a live exploit against someone else's network.
