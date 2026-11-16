# rovacomd: Status and Verification Report

Last updated: 2026-11-16. Slices 1-6 are complete: command line, listeners and main loop, inet transport, pmux mux, device list, control port, per-device relay, command service and token storage, USB link layer and recovery records, USB backend (nusb), device-initiated commands (D1, kept as C) and log port traces.

## Validation runs

| | macOS | Linux |
|---|---|---|
| Host | MacBook Air, macOS 27.3 (26C5035r), arm64 | a010, Ubuntu 26.10, kernel 7.3.0, x86_64, glibc 2.44 |
| Rust | rustc 1.100.0 stable | rustc 1.100.0 stable |
| Dependencies | libc 0.2.191, nusb 0.2.9, sha1 0.11.0 | same |
| Build profile | `panic = "abort"` (dev and release) | same |
| C reference | `scripts/build-reference.sh` (Apple clang 21.0.0), upstream 530a103 with `novacomd-macos.patch` and `novacomd-test-noroot.patch` | same script (gcc 15.3.0) |
| rovacom client | `../rovacom` debug build, and its C `novacom` reference | same |

Commands (run in the repository root): `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`.

## Verification report

| Item | macOS | Linux |
|---|---|---|
| fmt / clippy `-D warnings` | executed 2026-11-16, passed | executed 2026-11-16, passed |
| Unit tests | executed 2026-11-16, 123 passed | executed 2026-11-16, 122 passed (some tests are OS-specific) |
| Differential tests vs the C reference (CLI, daemon, inet, pmux, relay, command service, USB link layer, device commands, log port, pairings) | executed 2026-11-16, 91 passed | executed 2026-11-16, 94 passed (3 tests are Linux-only) |
| Device-command and log-port tests repeated | 25 of 25 passed (2026-11-04) | 20 of 20 passed (before the log-order fix) |
| Pairings {C novacom, rovacom, rovacom as `novacom`} × {C novacomd, rovacomd, rovacomd as `novacomd`}, one fake inet device | executed, passed | executed, passed |
| CI workflow (`.github/workflows/rust.yml`, unit tests only) | proposed, **never run** | proposed, **never run** |
| Linux arm64, macOS x86_64 | not executed (CI jobs proposed) | not executed |
| USB backend against a real device | **never executed**: only unit tests of pure functions | **never executed** |
| Real device (Palm Pre3) | blocked: not seen on the Mac's USB bus; on wifi, all probed TCP ports are filtered | n/a |

## Known limits

- The Linux C reference daemon is not a valid USB reference: with libusb-compat it calls `ioctl(USBDEVFS_BULK)` on a field that is no longer a file descriptor (`usb-linux.c:302,332`). Never run it with the Pre3 attached. The macOS build uses `usb_bulk_read`/`usb_bulk_write` and is usable.
- Test daemons (C and Rust) run with `ROVACOMD_TEST_NO_USB` set and do not start the USB scan, so a device plugged in during a test run is not claimed. The guard still refuses to start a test daemon while a Palm device is attached.
- Local denial-of-service paths are kept as in C (D7, D8, D10): any local process can stop or stall the daemon through ports 64022, 6971 and 12311.

## Remaining work before full replacement

1. Push the branch and run CI on real runners; add Linux arm64 and macOS x86_64 coverage.
2. Rehearse the USB backend against a fake USB device (for example `dummy_hcd` with FunctionFS in a Linux VM).
3. With per-action approval, read-only tests against the Pre3: enumeration with OS tools, then `rovacom -l`, `run file:///bin/uname -a` and `get file:///etc/palm-build-info`.
