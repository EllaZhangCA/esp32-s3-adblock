# Validation record

Validated locally on Windows on 2026-10-05 (America/Vancouver). See the GitHub Actions run for the current commit's Linux results.

## Automated checks

- Six PlatformIO configurations: `s3`, `s3-4mb`, `s3-16mb`, `s3-uart`, `s3-4mb-uart`, `s3-16mb-uart`.
- Firmware and LittleFS builds, actual binary S3 chip ID, bootloader Flash-size header, partition alignment/overlap/end and both OTA slot bounds.
- Python: hosts/plain/AdGuard input; exact allow rules and duplicates; www preservation; invalid/empty/missing input preserves previous output; known FNV vector; label limits; certificate-bundle reproducibility; all three partition layouts.
- Native C++: DNS flags/counts/classes/compression/truncation/label lengths/EDNS; output-buffer guards; 100,000 deterministic malformed packets; hash-table boundaries through 2.4 million entries; sorted-list validation; injected rename failures and simulated restart between renames.
- CI repeats the C++ tests with AddressSanitizer and UndefinedBehaviorSanitizer and compiles all six firmware/filesystem variants. CI firmware artifacts contain no WiFi or shared admin secrets.

## Required hardware acceptance (not yet performed)

1. Confirm module marking, actual Flash size/type, USB wiring and stable 5V power. Select the matching environment.
2. Flash firmware plus filesystem over USB. Verify the serial log identifies S3, reports a nonzero list and prints distinct web/setup passwords.
3. Verify WPA2 setup, a WiFi SSID containing quotes/angle brackets, login failure without credentials, and reboot persistence.
4. Test an allowed domain, blocked A and AAAA, custom rule, parent/subdomain, pause/resume, banned client and custom-only operation without a downloaded list.
5. Verify unauthenticated uploads fail, mutation GETs fail, POSTs without the CSRF header fail, and bad/unsorted/interrupted lists keep the old domain count.
6. Verify valid HTTPS updates after NTP, reject an untrusted certificate/HTTP downgrade/truncated download; interrupt power during list replacement and confirm recovery.
7. OTA the same profile, verify wrong-chip/corrupt images are rejected, and confirm USB recovery. Partition changes require USB.
8. Test 24-hour operation, concurrent clients, unavailable upstream DNS, router reboot/reconnect, throughput, thermal behavior and power interruption.

No hardware throughput, RF range, stable runtime duration or full compatibility claim is made until these checks are completed on the target boards.
