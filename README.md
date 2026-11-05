# rovacomd

A Rust port of [novacomd](https://github.com/openwebos/novacomd), the host daemon that connects webOS devices (such as the Palm Pre3) over USB or TCP to novacom clients. rovacomd keeps the C daemon's command line, ports, log output and wire protocol, works with both `novacom` and [`rovacom`](https://github.com/jauderho/rovacom), and also runs under the name `novacomd`. Linux and macOS are both supported.

- [Assessment of the C original](docs/ASSESSMENT.md): behavior, divergences (D1-D33) and decisions (Q1-Q7)

Licensed under Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Build and run

```bash
cargo build --release
./target/release/rovacomd -h
```

The options are those of novacomd (`-b`, `-t`, `-c`, `-e`, `-s`, `-d`, `-V`, `-h`). The daemon listens on 127.0.0.1 ports 6968 (device list), 6969 (emulator link), 6970 (log), 6971 (control), 12311 and 64022, plus one port per device. `-b` binds the device list, log, emulator and per-device ports to all interfaces.

rovacomd does not need root. On Linux the user needs access to the USB device nodes: `contrib/udev/60-rovacomd.rules` grants it to the logged-in user (install steps are in the file). The build does not install it.

Security note: as in C, a connected device (or a local process on port 6969) can read and write files as the daemon user and open local TCP connections (D1 in the assessment). Do not use `-b` on untrusted networks.

## Test

```bash
cargo test --lib
```

The differential tests (`cargo test --test differential`) run the same scenarios against rovacomd and the C novacomd and compare the results. They need:

- the C reference: `scripts/build-reference.sh` (builds into `reference/`, or set `ROVACOMD_REFERENCE`);
- a debug build of rovacom in `../rovacom` and its C novacom build (or set `ROVACOMD_RUST_CLIENT` and `ROVACOMD_C_CLIENT`).

They use the fixed ports, so they refuse to run while another novacomd is running, and they refuse to run while a Palm device is attached.

## Repository CI baseline

Baseline GitHub Actions used by this repository, plus a Rust workflow (format, clippy, unit tests on Linux and macOS):

- Adhere to least privilege principles for workflow permissions
- Use of commit hashes for pinning GitHub Actions dependencies
- Use of Dependabot to update commit hashes as necessary
- Use of [andrej-karpathy-skills](https://github.com/forrestchang/andrej-karpathy-skills/blob/main/CLAUDE.md) as CLAUDE.md starting point
- Use of OpenSSF's [Security Scorecard](https://github.com/ossf/scorecard) (SCORECARD_TOKEN setup required)
- Use of Step Security's [Harden Runner](https://github.com/step-security/harden-runner)
- Codespell
- Super-Linter
- Semgrep CE
- (optional) Sync commits to GitLab (GITLAB_TOKEN setup required)
  - Create PAT on GitLab with API, repo read and repo write permissions
  - Add PAT into GitHub repo as a secret named GITLAB_TOKEN
