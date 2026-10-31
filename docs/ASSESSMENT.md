# rovacomd: Phase 1 Assessment (Rust port of novacomd)

The port is named **rovacomd**. It is the server side of the protocol that the `rovacom` client (`~/projects/rovacom`, see its `docs/ASSESSMENT.md`) speaks, plus the USB (and TCP "inet") link to the device. Wire bytes, ports and command strings must stay identical so that unmodified `novacom`/`rovacom` clients and unmodified devices see no difference. novacom and novacomd were designed as a pair; rovacom and rovacomd must work as a pair too, and every mix must work: {rovacom, novacom} × {rovacomd, novacomd}, with the Rust binaries also invoked under the names `novacom` and `novacomd`.

Status: inspection only. No Rust code written. The source reading below did not build, run or modify the C tree; the reference builds are recorded in Section 9.1.
Legend: **[V]** verified by reading source; **[H]** hypothesis, not yet verified. Line numbers refer to the upstream commit below (for `src/host/usb-linux.c`, to `git show HEAD:src/host/usb-linux.c`, not the patched working copy).

## 1. Source under port

| Item | Value |
|---|---|
| Upstream | https://github.com/openwebos/novacomd |
| Commit | `530a10378af854fc0723b14f3f807d26a028070d`, 2014-09-03 10:52:29 -0700, "Merge branch 'develop'" (HEAD, 15 commits in history) [V] |
| Local copy | `reference/novacomd` (gitignored), made by `scripts/build-reference.sh` |
| Local change | `src/host/usb-linux.c` carries `scripts/patches/novacomd-test-noroot.patch` (test enablement: with `-DREFERENCE_NO_ROOT_CHECK`, Linux skips the root check) on top of `scripts/patches/novacomd-macos.patch` (macOS build enablement only: `#ifdef __linux__` around `<linux/usbdevice_fs.h>`, the two `USBDEVFS_BULK` ioctls and the `geteuid()` root check; non-Linux uses `usb_bulk_read/usb_bulk_write`). Everything below describes the unpatched code [V] |
| Size | 25 `.c` + 22 `.h`, ~8.6k code lines (tokei) [V] |
| License | Apache-2.0 (LG Electronics 2008-2014; older files HP). `NOTICE`: `sha1.c` (Paul E. Jones, "freeware"), `buffer.c/.h` (Dropbear, MIT), `zlib.h`/`adler32.c` (zlib license) [V] |
| Tests | None in the repository [V] |

## 2. Build targets and scope boundary

### 2.1 Targets from `CMakeLists.txt` [V]

There is exactly one target, executable `novacomd` (`add_executable`, line 66). Its sources depend on `WEBOS_TARGET_MACHINE_IMPL`:

| | `host` | `device` | `emulator` |
|---|---|---|---|
| Common sources | `src/lib/*.c` (`buffer.c`), `src/lib/cksum/*.c` (`adler32.c`, `sha1.c`), `src/novacom/*.c` (`buf_queue.c`, `commands.c`, `commands_device.c`, `lib.c`, `mux.c`, `packet.c`), `src/platform_pthreads.c`, `src/main.c`, `src/log.c`, `src/socket.c`, `src/transport.c`, `src/transport_inet.c`, `src/transport_usb.c` | same | same |
| Target sources | `src/host/*.c`: `commands_service.c`, `device_list.c`, `recovery.c`, `tokenstorage.c`, `usb-linux.c` | `src/device/*.c`: `auth.c`, `commands_service.c`, `usb-gadget.c` (+ `platform_pthreads.c` listed a second time, line 54) | same as device |
| Defines | `-DHOST=1 -DPLATFORM_PTHREADS=1 -DBUILDVERSION="${WEBOS_COMPONENT_VERSION}"` | `-DDEVICE=1 -DPLATFORM_PTHREADS=1 …` | same as device |
| Link | `pkg_check_modules(LIBUSB REQUIRED libusb)` → libusb-0.1 API (`usb.h`), `pthread`, `rt` | `nyx` (`pkg_check_modules(NYXLIB REQUIRED nyx)`), `pthread`, `rt` | same as device |
| Launch file | `files/launch/host/novacomd.conf.in` | `files/launch/device/novacomd.conf.in` | `files/launch/emulator/novacomd.conf.in` |

- Build system needs `include(webOS/webOS)` from `cmake-modules-webos` (`webos_modules_init(1 0 0 QUALIFIER RC4)`, `webos_component(2 0 0)`, `webos_machine_impl_dep()`, `webos_build_daemon(NAME novacomd LAUNCH …)`). Install paths come from those modules: [H] binary in `@WEBOS_INSTALL_SBINDIR@` (`/usr/local/webos/usr/sbin` by README default root), upstart file installed by `webos_build_daemon`. Modules are not in this repository.
- `BUILDVERSION` is `WEBOS_COMPONENT_VERSION`; [H] `"2.0.0"` from `webos_component(2 0 0)`.
- `src/novacom/lib.c:28` includes `<nyx/nyx_client.h>` unless `WEBOS_TARGET_MACHINE_IMPL_HOST` is defined. CMake never defines it explicitly; [H] `webos_machine_impl_dep()` does.
- `src/platform_other.c` is **never compiled** (not in any glob or list). It defines a second `platform_init` and `platform_checksuperuser` [V].
- The deleted `makefile` (removed in `ea5efcb`, visible with `git show ea5efcb^:makefile`) built host objects from `src/host/usb-$(HOSTOS).o` with `HOSTOS := linux` only. No macOS or Windows USB backend ever existed in this repository; comments in `transport_usb.c:811-812` ("MacOS uid = UID") refer to a backend that is not here [V].
- README says libusb **1.0** and GLib. The code uses the libusb **0.1** API (`usb_find_busses`, `usb_open`, `usb_claim_interface`) and contains no GLib reference [V].
- `-lrt` (line 85) has no macOS equivalent library [V]; reference-build feasibility is handled separately.

### 2.2 Launch and installer scripts [V]

| File | Content |
|---|---|
| `files/launch/host/novacomd.conf.in` | upstart: `start on runlevel [2345]`, `console output`, `respawn`, `exec @WEBOS_INSTALL_SBINDIR@/novacomd -b` (**binds all interfaces**) |
| `files/launch/device/novacomd.conf.in` | upstart, device only: migrates `/var/gadget` → `@WEBOS_INSTALL_EXECSTATEDIR@/novacomd`, mounts gadgetfs on `/dev/gadget` if `novacom_enabled` exists, `exec … novacomd > /dev/null`, `normal exit 0 TERM` |
| `files/launch/emulator/novacomd.conf.in` | upstart, emulator guest: waits up to 10 s for the default gateway (`route | grep "UG "`), then `exec … novacomd --connect-ip $ip_addr` |
| `installers/linux/scripts/novacomd-conf`, `novacomd-upstart` | upstart jobs for the Palm SDK layout, `exec /opt/Palm/novacom/novacomd`. **Not referenced by CMake** |

### 2.3 Scope boundary

| In scope for rovacomd (Linux + macOS host) | Device-only (out of scope) | Dead / not built |
|---|---|---|
| `main.c` (HOST paths), `log.c`, `socket.c`, `transport.c`, `transport_inet.c`, `transport_usb.c` (HOST paths), `platform_pthreads.c`, `novacom/*` (mux, bufq, command parser, packet), `lib/buffer.c`, `lib/cksum/sha1.c`, `host/*` | `src/device/*` (gadgetfs `usb-gadget.c`, `auth.c` with `/var/novacom/passwd` and `/var/novacom/tokens`, device `commands_service.c`), nyx, `DEVICE` branches in `transport_usb.c`/`commands_device.c`/`platform_pthreads.c`, device and emulator launch files | `platform_other.c`; `lib/cksum/adler32.c` (mux uses its own `adler()`, `mux.c:94`); `bufq_destroy_sleep`, `novacom_read_channel_sync`, `novacom_register_for_notifications`, `novacom_usbll_drop_offline`/`get_state`/`changeback_state` (host never calls); `transport_stop`, `platform_waitfor_thread` (would assert) |

The device side is needed only as a **test peer** (Section 7), never as a deliverable. `include/device/auth.h` is compiled into the host for constants only [V]. Note that the host build **does** include `src/novacom/commands_device.c` with its `get`/`put`/`connect` handlers (see D1); whether to port that path is open question Q2.

## 3. Architecture map

### 3.1 Startup sequence (`main.c:main`, 977-1108) [V]

1. `signal(SIGPIPE, SIG_IGN)`; `platform_init()` (`srand(time(NULL))`, recursive mutexes); `openlog("novacomd(" BUILDVERSION ")", 0, LOG_LOCAL7)` (HOST); `log_init()`.
2. `novacom_init()` → `novacom_nduid_init()`: host nduid = 40 random lowercase hex chars from `rand()` (`lib.c:40-43`), new every start.
3. `parse_commandline()` (getopt loop, side effects happen during parsing, see 3.2).
4. `novacomopt()` (799-854): TCP connect to `127.0.0.1:64022`; success → `Cannot start novacomd twice!`, `exit(0)`.
5. `-d`: fork, parent `exit(EXIT_SUCCESS)`; child `umask(0)`, `setsid()`, `chdir("/")`, close fds 0-2 (not reopened).
6. Bind listeners in this order: 6968 (`g_listen_all`), 12311 (loopback), 6970 (`g_listen_all`), 64022 (loopback), 6971 (loopback). Any failure → `error creating server sockets, port %d`, return 1.
7. `transport_init()`: `novacom_usb_transport_init()` (Linux: `geteuid() != 0` → `need to run as super user to access usb`, return 1; then `usb_init()`); inet init no-ops.
8. `transport_start()`: USB find-and-attach thread; inet listen thread (6969).
9. `main_loop()` forever. `main` never returns normally.

### 3.2 Command line (`getnextopt` 915-960, `handleopt` 856-905, `usage` 150-164) [V]

`getopt_long(argc, argv, "ht:c:e:s:bdCV", longopts, NULL)`; long options only `--connect-ip`(=`-c`), `--bind-all-interfaces`(=`-b`), `--daemonize`(=`-d`), `--version`(=`-V`). Options are handled one by one as parsed.

| Opt | Effect | Default / validation |
|---|---|---|
| `-b` | `g_listen_all = 1`: 6968, 6970, 6969 and per-device ports bind `INADDR_ANY` | loopback |
| `-t n` | `g_recovery_timeout = atol(n)` (USB recovery window, seconds) | 5; outside 2..5 (incl. junk → 0) → `Invalid timeout out of range(2~5 seconds): <n> ` (note trailing space) on stderr, then usage, exit 1 |
| `-e n` | `g_usbio_retry_timeout` ms | 100; capped at 500; no lower bound (negative accepted) |
| `-s n` | `g_usbio_retry_delay` ms | 50; capped at 500; after parsing, if timeout < delay then delay = timeout (971-973) |
| `-c h[:p]` | splits at first `:` or space (`strpbrk(addr, ": ")`); **immediately** starts an outbound inet connect thread to `h`, port `p` or 6969 | repeatable; IPv6 literals break on `:` |
| `-d` | daemonize after parsing | |
| `-C` | `g_cpuaffinity = 0` (already 0; no effect on host) | not in usage text |
| `-V` | `novacomd version <BUILDVERSION>` on stdout, **exit 1** | |
| `-h` | usage on stdout, **exit 1** | |
| other | getopt diagnostic (libc, stderr) → `Invalid command line option or parameter` (stderr) → usage (stdout) → exit 1 | |

Positional arguments are ignored silently. Usage text, each line prefixed by a timestamp (3.8):

```
Usage:  novacomd [option]...
options:
  -b                  bind ipaddress for remote access, default is 127.0.0.1 
  -t <seconds>        set recovery timeout interval, valid range 2 ~ 5, default is 5
  -c <host>:<port>    connect to specified IP address
  -e <io-retry-timeout>    timeout to retry packet I/O in milliesecond
  -s <io-retry-delay>    delay to retry packet I/O in milliesecond
  -d                  run in the background
  -V                  print version info
  -h                  display this help
```
preceded by an empty line (`"\n"` with timestamp). Trailing spaces on the `-b` line are in the source.

### 3.3 Layers

```
TCP clients (novacom/rovacom)                         device / emulator
   │ 6968 list, 6971 ctrl, per-device port              ▲
   ▼                                                    │
main.c main_loop (select) ── socketchan ── mux.c (pmux channels, ack/retransmit)
   │ commands_service.c / tokenstorage.c                │
   │                                         transport_usb.c (usbll link layer)
   │                                                    │
   │                                      usb-linux.c (libusb-0.1 + usbdevfs)   transport_inet.c (TCP 6969, no usbll)
```

- The daemon is an **opaque byte relay** between a client TCP socket and one mux channel. It never parses the client↔device 16-byte `0xDECAFBAD` stream framing (`main.c` does not include `packet.h`) [V].
- `transport.c` is a thin wrapper calling USB then inet init/start/stop [V]. There is no transport vtable: both transports call `novacom_go_online/go_offline`, `novacom_get_tx_packet`/`novacom_prepare_tx_packet` and `novacom_process_packet` directly [V].

### 3.4 Threads (all detached, 64 KiB stack, `platform_create_thread` asserts on failure) [V]

| Thread | Created at | Lifetime |
|---|---|---|
| main | — | `main_loop`, forever |
| USB find-and-attach | `novacom_usb_transport_start` (`usb-linux.c:607-613`) | forever; every 1 s: `novacom_usb_open()` rescan, `usbrecords_update(1)` |
| USB rx + tx (per claimed device) | `usb-linux.c:590-591` | until I/O error persists > `g_usbio_retry_timeout`; rx waits for tx, then stores a recovery record and frees the handle |
| inet listen (6969) | `inetlisten_transport_start` | forever |
| inet rx + tx (per TCP peer) | `transport_inet.c:256,178` | rx until bad header/short read/EOF; tx polls `novacom_get_tx_packet(…, 2000)` |
| inet connect (per `-c`) | `inetconnect_connect_to` (during option parsing) | forever, reconnect every 1 s, runs the rx loop inline |
| device init (per device with session id) | `novacom_register_device` (`main.c:363`) | opens channel 0x50, sends `logint` if a token is stored |
| device-initiated command workers | `commands_device.c` (`start_fds_thread`, reader/writer, `packet_thread`, `tcp_connect_thread`) | only if the peer opens a command channel on the host (D1) |

Callbacks (`socketchan_read_callback`, `socketcmd_read_callback`, `control_channel_rx_callback`, tx-completion callbacks) run on the transport rx thread while it holds the recursive `mux_mutex` [V] (`mux.c:403-492`). Lock order is `mux_mutex` → `device_list_mutex` (`novacom_go_offline` → `novacom_unregister_device`, `mux.c:760-767`) [V]. `platform_atomic_add` uses one global mutex (`platform_pthreads.c:274-283`) [V].

### 3.5 Main loop (`main.c:535-796`) [V]

`select()` with no timeout over: 6968, 64022, 12311, 6970, the accepted 12311 connection, 6971, every non-squelched client data socket, and every device listen socket (each device gets a temporary reference for the pass). Per readiness:

- **12311 (unblock)**: other threads call `unblock_main_loop()` (169-197), which lazily connects one global TCP socket to `127.0.0.1:12311` and sends one `0x00` byte. The main loop accepts it and drains one byte per pass.
- **64022 (opt)**: see 4.5.
- **6968**: `dump_device_list`, close.
- **6970**: `log_add_socket` (replaces any previous log listener).
- **6971**: `novacom_register_command(newsocket, NULL)`; closes the socket unless the command was queued for a device.
- **device port**: accept, set `O_NONBLOCK`, `novacom_register_client` → `novacom_open_temp_channel(…, command=1)` (synchronous, see D9) and `novacom_set_read_callback(socketchan_read_callback)`.
- **client data**: `recv_socket` up to 8192 bytes → `novacom_write_channel_async(…, ASYNC_FLAG_COPY, socketchan_write_callback)`. If the channel tx queue exceeds 64 KiB (`TX_QUEUE_UPPER`) the socket is squelched until it drains below 32 KiB (`TX_QUEUE_LOWER`). `recv` ≤ 0 marks the socketchan closed; it is destroyed at the top of the next pass (`shutdown(SHUT_RDWR)`, `close`, `novacom_close_channel`).
- Device → client: `socketchan_read_callback` `send()`s to the non-blocking socket. A partial or `EAGAIN` write returns −1, so the mux does **not ack** and the device retransmits after 50 ms; `partial_pos` remembers progress (199-239).

### 3.6 Mux, command service, logging, platform

- **Mux (`src/novacom/mux.c`)**: per-device `mux_instance` (refcounted) with a channel list. Per channel: tx `buf_queue`, stop-and-wait (one unacked packet), retransmit after `RETRANSMIT_WAIT_PERIOD` 50 ms, one pending ack flag. Contract in 4.8.
- **Command parser (`commands.c:178-314`)**: `<verb> [verbargs…] <scheme>://<path> [args…]`; whitespace tokenizer with `\` escapes; at most 4096 tokens; leading/trailing whitespace and trailing control chars trimmed.
- **Host command service (`host/commands_service.c`)**: verbs `list host`, `login dev`, `logout dev`, `logint dev`, `add dev`, `remove dev` (283-297). Device verbs are queued per device (`socketcmd_t` TAILQ in `active_device`) and sent on mux channel `0x50` (`PMUX_CHANNEL_CMDSERVICE`) using Dropbear-style `buffer_t` encoding (4.6).
- **Token storage (`host/tokenstorage.c`)**: 4.11. **Recovery (`host/recovery.c`)**: USB session resume records, 4.7.
- **Logging (`log.c`)**: 3.8 / 4.12.
- **Platform (`platform_pthreads.c`)**: pthread mutex (recursive), rwlock, events (mutex+cond, single-shot `if` wait), time via `gettimeofday`, `platform_abort` writes to address 0 then `abort()`. `malloc/printf/fprintf` are poisoned by macros (`platform.h:119-122`, `log.h:50-51`) [V].

### 3.7 Signals, shutdown, ownership [V]

- Only `SIGPIPE` is ignored. No other handlers: `SIGTERM`/`SIGINT` kill the process with no cleanup. `transport_stop()` is never called. There is no graceful shutdown path.
- `active_device` refcount: list (1), each `select` pass, device-init thread, non-empty command queue. Last `remove_device_ref` frees strings and closes the device listen socket (`main.c:473-493`).
- `mux_instance` refcount: `go_online` (1), `novacom_register_device`, each `socketchan`/`socketcmd`, inet tx thread, transient retains in `novacom_usbll_prepare_tx_packet`. Last release frees (`mux.c:117-123`).
- A USB disconnect does **not** immediately take the device offline: the usbll handle (and its mux) is parked in the recovery list for `g_recovery_timeout` (4.7).

### 3.8 Logging (`log.c`) [V]

- Masks: console `ALWAYS|ERROR`; syslog `ALWAYS|ERROR|TRACE`; log socket `ALWAYS|ERROR|TRACE|SPEW|MUXTRACE|LLTRACE` (33-37).
- Console: `LOG_ERROR` → **stderr**, everything else → **stdout** (via stdio, so fully buffered when not a tty [H] for output ordering).
- Every message is prefixed unless `LOG_NOTIMESTAMP`: `"[%d/%d/%d %d:%02d:%02d] "` (year/month/day hour:min:sec, local time, month/day/hour not zero-padded) (`platform_pthreads.c:300-309`).
- Messages are truncated to 256 bytes including the timestamp (`msg[256]`, `vsnprintf` size `256 - ts - 2`).
- Syslog: Linux only (`#elif defined(__linux__)`, 152): `syslog(LOG_ALWAYS /* =1 = LOG_ALERT */, "%s", msg_without_timestamp)` with ident `novacomd(<BUILDVERSION>)`, facility `LOG_LOCAL7`. macOS: no syslog.
- Log socket (6970): one listener at a time, `send(…, MSG_DONTWAIT)`; error other than `EAGAIN` closes it.
- Several messages embed C source positions: `LOG_PRINTF` on HOST is `log_printf(LOG_ALWAYS, "%s:%d: "…, __PRETTY_FUNCTION__, __LINE__)` (`debug.h:56`), e.g. `transport_usb.c:359` ("sending rst"); `usb-linux.c:431,452,466,298` print `__FUNCTION__:__LINE__`; `socket.c:110` and `main.c:769,780` print `__FILE__:__LINE__`. The macOS patch shifts `usb-linux.c` line numbers by up to +15, and `__FILE__` depends on the compiler invocation path [V].

## 4. Compatibility contract

### 4.1 TCP ports [V]

| Port | Bind | Served by | Behavior |
|---|---|---|---|
| 6968 `NOVACOM_DEVLISTPORT` | loopback, or any with `-b` | main loop | write device list, close |
| 6969 `NOVACOM_INETPORT` | loopback, or any with `-b` | inet listen thread | device/emulator link (4.9) |
| 6970 `NOVACOM_LOGPORT` | loopback, or any with `-b` | main loop | log stream to the latest connected client |
| 6971 `NOVACOM_CTRLPORT` | loopback only | main loop | host control commands (4.3) |
| 12311 `NOVACOM_UNBLOCKPORT` | loopback only | main loop | internal wake-up channel |
| 64022 `NOVACOM_OPTPORT` | loopback only | main loop | single-instance probe + option injection (4.5) |
| ephemeral, one per device | loopback, or any with `-b` | main loop | per-device data relay (4.4) |

All listeners: IPv4 only, `SO_REUSEADDR`, `FD_CLOEXEC`, `listen(SOMAXCONN)` (`socket.c:33-72`). Accepted sockets get `FD_CLOEXEC`.

### 4.2 Device list (6968) [V]

`dump_device_list` (`main.c:268-292`), one `send` per device, newest device first (devices are prepended), devices with `closing` skipped:

```
"%d %s %s %s\n"      port nduid conntype devtype
"%d %s %s %s %s\n"   ... sessionid   (only if the SYN carried a non-empty sn: token)
```

- `conntype`: `usb` (USB) or `tcp` (inet). `devtype`: inet → `emulator`; USB → the SYN `id:` token if present, else the `usbid_list` name if non-empty, else `[unknown]` (`mux.c:711-734`). `id:` value limited to 63 chars, `sn:` to 15, `mode:` to 15 (`devname[64]`, `sessionid[16]`, `devmode[16]`), split on `" \t\n"`.
- nduid: the 40 bytes from the peer, unvalidated (D20).
- Port 0 if the device listen socket failed (D11).
- The `inactive` flag (set while token login runs) is never read: such devices **are** listed (D21).

### 4.3 Control port (6971) [V]

Request: one `recv` of at most 127 bytes; must contain a NUL within the first 127 bytes (always true because the buffer is zeroed, unless 127 non-NUL bytes arrive). EOF yields an empty command. Parsed with `parse_command`.

| Request | Daemon action | Reply on the socket |
|---|---|---|
| `list host://…` | `dump_device_list` | device list lines (4.2), close. **No `ok` line** |
| unknown verb/scheme, parse error | — | nothing, close |
| `login\|logout\|logint\|add\|remove dev://<path> …` with no device whose nduid is a case-insensitive **prefix** of `<path>` (empty path = first device), or device without session id, or alloc failure | — | `"invalid command\n\0"` (NUL included), close |
| same, device found | queued on the device; sent on channel 0x50 when it reaches the head | later: success `"ok 0\n\0"`; device reported failure (for any verb) `"Novacom device login failed - incorrect password provided.\0"` (no newline); local send/encode error `"err -1\n\0"`; then close |

Argument rules: `login`/`logint`/`add` need ≥1 arg; `remove` needs ≥1 arg, a 10-char session id and a stored token; `logout` takes none (`commands_service.c:69-280`).

### 4.4 Per-device port [V]

- Accept → open a new host channel (numbers from `0x1000` upward, wrap at `0x7fffffff`, skipping live ones) with `PMUX_CONTROL_OPEN_COMMAND`, blocking until the device acks (D9). Then bytes are relayed both ways unchanged. The client's first line (e.g. `run file:///bin/ls\n`) is interpreted by the **device**, which replies `ok 0\n` or `req:auth\n\0` / `unrecognized command\n\0` (`commands_device.c:342,1000,1009`).
- Client EOF/error → channel close (`PMUX_CONTROL_CLOSE` once the tx queue drains). Device closes channel → client socket `shutdown(SHUT_RDWR)` + close.
- Coalescing: the mux packs all queued bytes of a channel into one packet up to the payload limit (`bufq_peek_nonblock`, `mux.c:583-585`); control-channel messages go one buffer per packet (`bufq_peek_onechunk_nonblock`). The device parses one packet as one command [V for device code], so packetization is observable [H for real firmware].

### 4.5 Option port (64022), unblock port (12311), log port (6970) [V]

- 64022: blocking `accept`; `SO_RCVLOWAT 4096`; `recv` of two native-endian `uint32_t` lengths; if `l0 != 0 && l0 + l1 < 4096` read `l0+l1` bytes, NUL-terminate, call `handleopt(buf, buf + l0)`. So any local process can trigger `version`/`help` (daemon `exit(1)`), `connect-ip`, `bind-all-interfaces`, etc. The sending side in `novacomopt` is `#if 0`; the only live use is the startup probe.
- 12311: see 3.5. Externally visible only as an occupied loopback port.
- 6970: plain text log lines (same text as console, with timestamps).

### 4.6 Host ↔ device service channel 0x50 [V]

Opened by the device-init thread with `PMUX_CONTROL_OPEN_COMMAND` (`main.c:1134`). Messages use `buffer_t` (`lib/buffer.c`): byte, byte, then strings as **big-endian u32 length + bytes** (`buffer_putint32`, 199-209).

| Host request | Bytes |
|---|---|
| login (password) | `50` `0` str(`"password"`) str(hash) |
| logint (token) | `50` `0` str(`"token"`) str(hash) |
| logout | `1` `0` |
| add | `70` `0` str(hash) |
| remove | `71` `0` str(hash) str(40-byte token hash) |

Device reply: `type` `version` `cmd` [blob]. `type` 51 = failure, 52 = success, 75 = token reply (for `add`, followed by a big-endian length + token bytes, stored as the token file). `remove` success deletes the token file (`commands_service.c:397-463`). Device side constructs the same layout (`src/device/commands_service.c:54-58,104-108,158-160,190-192`).

Automatic token login: when a device registers with a session id, the device-init thread computes `hex(SHA1(token[0..256] ‖ sessionid[10]))` (lowercase, `sha1.c:126-127`) from `~/.nova/<nduid>` and queues `logint dev://<nduid> <hash>` with no client socket (`main.c:1158-1169`).

### 4.7 USB link layer (`transport_usb.c`, `transport_usb_struct.h`) [V]

All integers **host-native** byte order (no conversion anywhere); the device is little-endian ARM [H], so the port encodes explicit little-endian.

```
usbll_header (20 B): u32 magic=0x7573626c 'usbl', u32 version=1, u32 txid, u32 rxid, u32 command
command: 0=null, 1=rst, 2=syn, 3=data
usbll_syn_header (60 B): u8 nduid[40], u32 mtu, u32 heartbeat_interval, u32 timeout, u32 data_offset, u32 data_length
```

- Device matching (`usb-linux.c:189-251`, `99-187`): VID/PID in `usbid_list` (95 entries, `host/device_list.c`), then the first interface/altsetting with class `0xff` (`USB_CLASS_VENDOR_SPEC`), subclass `0x47`, protocol `0x11`, `endpoint[0]` IN and `endpoint[1]` OUT; `usb_claim_interface`. Already-claimed devices fail the claim and are skipped. No set-configuration, no altsetting.
- Received packets with `len < 20`, wrong magic or version ≠ 1 are logged and treated as a failed read (`usb-linux.c:295-301`).
- First rx read uses timeout 5000 ms and length 16384; then the usbll handle is created (`novacom_usbll_create(devtype, 16384, 0, 2000)`: heartbeat 1000 ms, timeout 2000 ms) or a recovery record is matched (below).
- Handshake, host side: the host **never initiates** SYN. In `listen`, a received SYN (from the device, which sends one at most every 500 ms) records the remote nduid, `mtu = min`, `heartbeat = min`, `timeout = min` (as `int`), then the "nova68 workaround": `timeout == 7200000` → −1, `heartbeat == 1000` → −1 (so a default peer yields heartbeat 999). Short SYNs: < 52 bytes → heartbeat 250, timeout 1000; mtu taken only if `syn_len > 44`. Syn data (`id:…`, `sn:…`, `mode:…`) taken if `data_offset/data_length` fit. Then **`novacom_go_online` immediately** (device appears in the list), `remoteid = txid`, state `synrecv`. The next tx sends the host SYN (`txid = sessionid`, `rxid = remoteid`, host nduid, mtu, heartbeat, timeout; length 80, or `20 + device_syn_len` if the device's SYN was shorter) and moves to `established`.
- Established: tx `data` = usbll header + one pmux packet; `null` (header + 41 bytes host nduid incl. NUL) when nothing was sent for `heartbeat_interval` ms; rx `null` with `rxid == sessionid` ignored.
- Reset: rx packet with `rxid ∉ {sessionid, 0}` (non-rst) or any data/null before established → schedule `rst` with swapped ids, 61 bytes. rx `rst` with `rxid == sessionid` → `novacom_usbll_drop_offline` (device goes offline, new random session id, state `listen`). rx SYN while established with a different `txid` → bad packet.
- Odd-length rule: if a tx packet length is a multiple of 64 and below the buffer size, one extra (stale) byte is appended (`transport_usb.c:488-490`).
- Timeouts: bulk I/O timeout = negotiated `timeout`; on read/write failure retry every `g_usbio_retry_delay` ms until `g_usbio_retry_timeout` ms have passed, then shut the link down (`usb-linux.c:357-385,428-455`). Bad usbll packets sleep `g_usbio_retry_delay`.
- Recovery (`host/recovery.c`): at link shutdown the rx thread stores `{magic, version, txid = device txid, rxid = host sessionid}` with the live usbll handle for `g_recovery_timeout` seconds (decremented by 1 each second, destroyed when < 0, i.e. ~6 s at default 5). A newly attached device whose first packet header matches resumes the same usbll handle, mux, channels and device port. A SYN from a device with the same nduid discards its record (`novacom_usb_transport_deviceonline`, Linux-guarded call at `transport_usb.c:612-615`).

### 4.8 Mux (`mux.h`, `mux.c`) [V]

```
pmux_header (28 B): u32 magic=0x706d7578 'pmux', u8 version=3, u8 _pad, u16 flags (1=ACK),
                    u32 channel, u32 sequence, u32 payload_len, u32 total_len, u32 crc, data[]
control payload (12 B): u32 op, u32 channel, u32 len=12
op: 0=NONE 1=CHANNEL_CLOSED 2=OPEN 3=OPEN_COMMAND 4=CLOSE
channels: 0 null, 1 control, 0x50 cmdservice, ≤0xfff fixed, host temp 0x1000..0x7fffffff, device temp 0x80000000..
```

- Rx accepted if magic/version match, `total_len ≤ len`, `payload_len ≤ total_len`; `crc` = Adler-32 of the payload, `0` means "not checked". Channel 0 ignored. Unknown channel > 1 → reply `CHANNEL_CLOSED`.
- Data with `sequence == rx_sequence` → re-ack; `rx_sequence + 1` → deliver, ack only if the callback returns ≥ 0; other → log `RX PKT OUT OF SEQUENCE…` and drop. Closing channels ack everything.
- ACK: `flags=1`, `sequence = rx_sequence`, no payload, `crc=0`. In-sequence ack consumes the outstanding bytes and fires tx callbacks.
- Tx priority per call: one pending ack; else the first channel whose unacked packet is ≥ 50 ms old (retransmit same sequence and payload); else the **last** channel in the list with queued data. Sequence starts at 1 per channel.
- Remote `OPEN`/`OPEN_COMMAND` create the channel locally; `OPEN_COMMAND` on a channel > 0xfff installs the generic command handler **also on the host** (D1). `CLOSE`/`CHANNEL_CLOSED` shut the local channel.
- Payload limit: USB `mtu − 20 − 28` (mtu ≤ 16384); inet `4096 − 28`.

### 4.9 Inet transport (6969, `-c`) [V]

```
syn  (48 B, both sides send first, then read): char magic[8]="nduid: \0", char nduid[40]
frame: char magic[8]="ELTSDIM\0", u32 packetlen (native), then packetlen bytes = one pmux packet (no usbll layer)
```

- Registered as `go_online(nduid, "tcp", "emulator", NULL)`: **no session id, so no auth** on inet devices. Before registering, any existing device whose nduid matches (case-insensitive, length of the existing id up to 40) is unregistered (`novacom_removedup_device`, VirtualBox workaround) — only for `tcp` registrations.
- Tx thread sends a `packetlen = 0` frame every 2 s when idle (keepalive). Rx: one `recv` each for header and body relying on `SO_RCVLOWAT 4096`; short read, wrong magic or `packetlen > 4096` ends the link. `TCP_NODELAY`; `TCP_QUICKACK` on Linux only.
- The emulator launch file uses this from the guest side (`--connect-ip <gateway>`), so a host `novacomd` listening on 6969 serves the emulator.

### 4.10 End-to-end stream framing

The client ↔ device stream (`packet_struct.h`: header `0xDECAFBAD`, version 1, size, type DATA/ERR/OOB; OOB EOF/SIGNAL/RETURN/RESIZE) is identical to the client assessment and passes through the daemon unchanged [V]. The daemon itself only produces that framing in the device-initiated command path (`packet.c`, D1).

### 4.11 Token storage (`host/tokenstorage.c`) [V]

- Directory: `getpwuid(getuid())->pw_dir + "/.nova/"`, created `mkdir(…, 0700)`; `$HOME` is not used. Path buffer 128 bytes.
- File: `<dir><nduid>`, raw token bytes as received (`fopen "wb"`, mode `0666 & ~umask`; `umask(0)` under `-d`). Hash use reads exactly 256 bytes (`NOVACOM_AUTHTOKEN_LEN`) and requires a 10-char session id.
- Linux root: `/root/.nova/`; macOS root: `/var/root/.nova/`; non-root (macOS patched build): the user's home [V for code, H for real paths].

### 4.12 Notable console lines (all with timestamp prefix) [V]

stdout (`LOG_ALWAYS`): `dev '%s' via %s type %s`, `novacom_go_online:%s` (`__PRETTY_FUNCTION__`), `removing id %s`, `duplicate: '%s', port %d`, `Connecting to %s/%s via IP`, `starting the daemonizing process`, `Cannot start novacomd twice!`, `novacomd version %s`, USB retry statistics (`usb-linux.c:362,384,431,452`), `…:359: usbll(%08x) sending rst, txid=0x%08x, rxid=0x%08x`.
stderr (`LOG_ERROR`): `Invalid command line option or parameter`, `Invalid timeout out of range(2~5 seconds): %s `, `error creating server sockets, port %d`, `need to run as super user to access usb`, `unable to create socket`, `unable to connect`, USB header errors (`Invalid USB packet length. Make sure your novacomd versions match.`, `Got bad USB packet. Make sure your novacomd versions match.`, `Got packet with old usb transport header, please upgrade the other end`, `Got packet with newer usb transport header than we support, please upgrade to newer version`), `Got RESET packet, process it?, rxid=0x%08x, sessionid=0x%08x`, `Got RESET packet, restart...`, `Recovered record...`, `failed to find acceptable endpoints`, `Got old syn USB packet. Adjusting packet length`, `invalid connection packet, read(%d/%d)`, `Unable to create socket(errno %d)`, `[%d] RX PKT OUT OF SEQUENCE …`, `ASSERT FAILED at (%s:%d): %s`.

### 4.13 Exit codes [V]

| Situation | Output | Exit |
|---|---|---|
| `-V` / `--version` | stdout version line | 1 |
| `-h` | usage (stdout) | 1 |
| unknown option, missing argument, bad `-t` | libc getopt text (stderr, only for getopt errors), error line (stderr), usage (stdout) | 1 |
| second instance (64022 connect succeeds) | `Cannot start novacomd twice!` (stdout) | 0 |
| `-d` parent | `starting the daemonizing process` | 0; child `fork/setsid/chdir` failure → 1 |
| listener bind/listen failure | `error creating server sockets, port N` | 1 |
| Linux, euid ≠ 0 | `need to run as super user to access usb` (after binding all listeners) | 1 |
| `platform_assert` failure | assert line, then SIGSEGV | signal |
| normal operation | never exits; terminated by signal | signal |

Order matters: `-V`/`-h`/option errors are reported before the single-instance check, which precedes daemonizing, which precedes binding.

### 4.14 Constants and timeouts [V]

| Constant | Value | Where |
|---|---|---|
| mux retransmit | 50 ms | `mux.c:38` |
| USB SYN interval (device) | 500 ms | `transport_usb.c:60` |
| heartbeat default | 1000 ms (host effective 999) | `transport_usb.c:61`, 595-596 |
| link timeout default | 5000 ms (`TIMEOUT_PACKET`); host creates with 2000 | `transport_usb.c:62`, `usb-linux.c:476` |
| USB I/O retry timeout / delay | 100 / 50 ms, max 500 | `transport.h:24-25`, `main.c:53-54` |
| recovery window | 5 s (2..5) | `transport.h:22` |
| max MTU | 16384 | `transport.h:23`, `usb-linux.c:48` |
| USB rescan | 1 s | `usb-linux.c:595` |
| inet keepalive / max frame | 2000 ms / 4096 | `transport_inet.c:91,49` |
| inet reconnect | 1 s | `transport_inet.c:336` |
| client tx squelch | 64 KiB / 32 KiB | `main.c:69-70` |
| client recv chunk | 8192 | `main.c:543` |
| control command max | 127 bytes | `main.c:1197-1203` |

### 4.15 Filesystem and environment [V]

No configuration files and no environment variables are read on the host (`getenv` absent; `setenv` only in the device shell path). Runtime paths: `~root`-style `.nova` token directory (4.11), libusb device nodes (Linux `/dev/bus/usb` [H, inside libusb-0.1]). `-d` chdirs to `/`.

### 4.16 Agreement with the client (`rovacom/docs/ASSESSMENT.md`)

| Topic | Result |
|---|---|
| Device list format vs client `sscanf("%d %40s %20s %30s %10s")` | Agree for nduid (40), conntype, session id (10). **Disagree** if devtype > 30 chars: the daemon allows up to 63 from `id:`; the client would read the rest of devtype as the session id [V both sides, H that real devices send such names] |
| Client `-c list` (`"list host://"`, expects a line starting `ok`) | **Disagree**: the daemon replies with raw device lines and never `ok`, so `novacom -c list` always exits 1 (`bad or error response from other side: '…'`) [V both sides by reading; not executed] |
| `-c login/add/remove` without newline, `logout` with `\n` | Agree: one `recv`, `trim()` removes the newline; replies `ok 0\n\0` satisfy the client's `ok` prefix test [V] |
| Login failure | Daemon sends `Novacom device login failed - incorrect password provided.` (no `\n`); client prints it inside `bad or error response …` [V] |
| Auth hash | Client computes `hex(SHA1(hex(SHA1(nduid‖pw))‖session))`; the daemon forwards it opaquely to the device [V] |
| `req:auth` | Produced by the **device** on the per-device channel, relayed unchanged [V] |
| Stream framing, OOB codes | Not touched by the daemon [V] |

## 5. Platform-specific code and portability risks

### 5.1 Conditional code [V]

| Location | Condition | Effect |
|---|---|---|
| `usb-linux.c:36,294,319` | (unconditional upstream) | `<linux/usbdevice_fs.h>`, `ioctl(fd, USBDEVFS_BULK)` on the fd taken from libusb-0.1's private `usb_dev_handle` (`myhandle->fd`, 52-64) |
| `usb-linux.c:270` | (unconditional upstream) | `geteuid() != 0` → fail |
| `transport_usb.c:612` | `__linux__` | recovery-record discard on SYN only on Linux |
| `transport_inet.c:190` | `__linux__` | `TCP_QUICKACK` |
| `log.c:25,152` | `__linux__` | syslog only on Linux |
| `main.c:56,917` | `!W32` | `-d` exists (always true on Linux/macOS) |
| `platform_pthreads.c:324,396,420` | `DEVICE` | heap lock, CPU affinity (device only) |

### 5.2 Risks

| # | Area | Linux | macOS | Note |
|---|---|---|---|---|
| P1 | USB I/O | usbdevfs ioctl, needs root (or device-node permissions) | no usbdevfs; patched build uses libusb-0.1 API over libusb-compat over libusb-1.0 (IOKit) | Rust needs two backends; real Palm macOS daemon source is not available [V] |
| P2 | libusb private struct hack | correct only with original libusb 0.1.12 (`fd` first); with libusb-compat-0.1 the first field is a pointer | n/a after patch | [H] which libusb a010 provides |
| P3 | root check | exit 1 if not root (test reference: skipped by `novacomd-test-noroot.patch`) | removed by patch | port behavior is Q3 |
| P4 | getaddrinfo error sign | `EAI_*` negative in glibc: `r < 0` works | `EAI_NONAME = 8` (SDK `netdb.h:195`): `r < 0` misses errors → NULL deref (D5) | [V] |
| P5 | `select` / `FD_SETSIZE` 1024 | silent overflow | [H] libc may abort on `FD_SET` overflow | Rust should use `poll` (no visible change below 1024 fds) |
| P6 | `SO_RCVLOWAT` + single `recv` | [H] waits for min(lowat, len) | [H] same in XNU `soreceive`, edge cases differ | Rust should loop `read_exact` (same bytes, fewer false disconnects) |
| P7 | `SO_REUSEADDR` | duplicate listen fails | [H] BSD may allow a second bind to a specific address when a wildcard bind exists (matters with `-b`) | single-instance check uses 64022 connect, not bind |
| P8 | syslog | yes, priority `LOG_ALERT` | none | keep per-OS behavior |
| P9 | root home | `/root` | `/var/root` | token path |
| P10 | getopt diagnostics | glibc text with `argv[0]` | BSD text with basename | as in the client port |
| P11 | `-lrt`, `-fcommon` | ok / D26 | no `librt` | reference-build only |
| P12 | `fork` after threads | `-c` thread lost (D6) | same; also libusb-1.0 on macOS starts a CoreFoundation thread at init [H], but init happens after fork | |
| P13 | Byte order / layout | all structs native-endian, packed by natural alignment (sizes 20/60/28/12/12/48/16) | same | Rust: explicit LE codecs, size assertions |

## 6. Suspected bugs (flagged, not fixed)

| # | Location | Defect | Observable effect |
|---|---|---|---|
| D1 | `mux.c:897-900,1072-1078`; `commands_device.c:975-986,996-1004` | The host accepts `PMUX_CONTROL_OPEN_COMMAND` from the peer and installs the command handler; on HOST the auth check is compiled out and `get file://`, `put file://` (mode 0775), `connect tcp-port://` are available | Any device or any process that can reach 6969 can read/write host files and open loopback TCP connections with the daemon's privileges (root on Linux) |
| D2 | `tokenstorage.c:89,122,145` | Peer-controlled nduid used as a file name without validation | Path traversal (`../`) for token write/read/remove |
| D3 | `tokenstorage.c:122,145` | `strncat(path, file, sizeof(path) - strlen(path))` misses the `-1` | 1-byte stack overflow with long home paths |
| D4 | `main.c:1023`, `tokenstorage.c:92` | `-d` sets `umask(0)`; token files created 0666 | Mitigated by the 0700 directory |
| D5 | `transport_inet.c:307-321` | `getaddrinfo` failure tested with `r < 0` | macOS: `-c badhost` dereferences NULL `res` → crash |
| D6 | `main.c:867,996` vs `1012` | `-c` starts its thread during option parsing, before `fork` | `-d -c host` silently never connects; `-c` thread also runs in an instance that then exits "twice" |
| D7 | `main.c:664-696` | Opt port: blocking accept/recv in the main loop, unauthenticated option injection (`version`/`help` → `exit(1)`), `l0 + l1` u32 wrap lets `val = &buf[l0]` point past the buffer | Local DoS / kill; out-of-bounds read |
| D8 | `main.c:717-724,1202-1217` | Control port: blocking `recv` in the main loop; single `recv` | A silent client stalls the whole daemon; commands split across segments are truncated |
| D9 | `main.c:513` → `mux.c:931,229` | `novacom_open_channel` waits for the device ack with no timeout, on the main thread | Main loop frozen while the device is slow or until the recovery window expires |
| D10 | `main.c:169-197,652-662` | Unblock: `recv` returning 0 not handled; a second connection to 12311 replaces (leaks) the first; global `unblock_fd_write` used by many threads without a lock | 100% CPU loop after EOF; a local process can hijack 12311; fd races |
| D11 | `main.c:367-370,623,637` | `select` with fds ≥ `FD_SETSIZE`; device with failed listen socket gets `FD_SET(-1)` and is listed with port 0 | UB / crash with many clients; bogus list entry |
| D12 | `log.c:128-161` | `vsnprintf` return value used as length after truncation | Log socket gets up to ~len bytes past `msg[256]` (stack over-read) for long messages |
| D13 | `log.c:158-188` | `log_socket` shared across threads without a lock | Double close / write to a reused fd |
| D14 | `transport_usb.c:603-606` | SYN `data_offset + data_length` u32 wrap unchecked; `data_length == 0` passes | Device-controlled out-of-bounds NUL write (`syn_data[data_length-1]`) |
| D15 | `transport_usb.c:585-590` | Heartbeat/timeout from the device accepted as `int` without lower bound | 0 or negative values: null packet every tx call / bulk timeout 0 (usbdevfs: no timeout [H]) |
| D16 | `transport_usb.c:356`, `488-490` | `rst` packet sends 41 unwritten bytes; odd-length pad byte is stale | Residual buffer content on the wire (nondeterministic bytes) |
| D17 | `mux.c:385-395,461-464` | No `len >= 28` check; `payload_len` not bounded by `len - 28` | Adler-32 and rx callback read up to 28 bytes past the packet |
| D18 | `usb-linux.c:120,142-145` | Loop bound uses `interface->num_altsetting` (interface 0) for every interface; `endpoint[1]` read without checking `bNumEndpoints` | Out-of-bounds read on unusual descriptors |
| D19 | `usb-linux.c:384,452` | `%ld` given `unsigned int`/`int`; `et` may be uninitialized | Garbage numbers in log lines (UB) |
| D20 | `transport_inet.c:165-169`, `transport_usb.c:576-577` | Peer nduid accepted as any 40 bytes (space, newline, NUL) | Corrupts device list lines; truncated ids |
| D21 | `main.c:104,362,1178` | `inactive` written, never read | Devices listed while token login runs (intent in comment not implemented) |
| D22 | `main.c:1385-1430` vs `1239-1312` | `cmd_queue` modified on the transport thread without `device_list_mutex`, and on the main thread with it | Data race on the TAILQ |
| D23 | `main.c:199-239,585-598` | `socketchan.close/channel` written by the transport thread, read and freed by the main thread unsynchronized | Data race (UB) |
| D24 | `main.c:430-433` | `cmd_chan` never freed | Leak per authenticated device session |
| D25 | `platform_pthreads.c:207-216` | `pthread_cond_wait` under `if`, not `while` | Spurious wakeup returns early; sync callers then destroy stack events still referenced (`mux.c:229-239`) [H] |
| D26 | `recovery.c:45`, `usb-linux.c:94-95` | `t_recovery_queue` defined non-static in two files; second unused static `recovery_lock` | Link error under `-fno-common` (GCC ≥ 10, Clang ≥ 11 default) [H for toolchains] |
| D27 | `transport_inet.c:103,157,183,196` | `send` result ignored; single `recv` per field | Partial writes corrupt the stream; partial reads drop the link |
| D28 | `main.c:776-781` | `sdata` not terminated when `len == 8192`, then printed | Over-read into trace (syslog on Linux) |
| D29 | `socket.c:103-116` | On `EWOULDBLOCK`, sleeps 1 ms up to 1000 times on the main thread, logging each try to stderr | Up to 1 s stall and 1000 error lines |
| D30 | `lib.c:41`, `lib.c:84`, `platform_pthreads.c:47` | nduid and session ids from `rand()` seeded with `time(NULL)`, `rand()` called from many threads | Predictable ids; two daemons started in the same second share an nduid |
| D31 | `main.c:1039-1041` | Std fds closed, not reopened | Console logs go to whatever owns fds 1/2 (listen sockets, so `send` fails) [H harmless] |
| D32 | `main.c:252` | `sc->channel > 0` true for `(uint32_t)-1` | `close_channel(0xffffffff)` on failed sockets (returns −1, harmless) |
| D33 | `main.c:1243-1246` | Device chosen by nduid **prefix** of the URL path; empty path → first device | Commands may hit the wrong device if ids differ in length (inet peers) |

Unsafe or nondeterministic defects are candidates for "intentionally changed" (as decided for the client port); deterministic quirks (NUL-terminated replies, no `ok` for `list`, prefix matching, 999 ms heartbeat, odd-length padding rule, timestamps) are candidates to preserve. Decision pending (Q2, Q5).

## 7. Hardware vs mock testing

| Behavior | Needs the Pre3 over USB | Testable without hardware |
|---|---|---|
| CLI, exit codes, messages, single-instance, daemonize | | yes (both OSes; C reference runs as user on both, see 9.1) |
| Ports 6968/6970/6971/12311/64022 | | yes |
| Inet transport, device registration, device list, keepalive, duplicate removal | | yes: a fake device speaking 4.9 against TCP 6969 |
| Mux (open/close channels, ack, retransmit, squelch, CHANNEL_CLOSED) and per-device relay | | yes via the fake inet device (same pmux bytes as USB minus usbll) |
| Device-initiated command path (D1) | | yes via inet |
| Service channel, `login/add/remove/logout`, token storage, auto `logint` | **inet devices have no session id**, so only reachable via USB SYN data | via a Rust unit harness of `novacom_service_*`, or a C harness that links `commands_service.c`+`tokenstorage.c` with stubs; not end-to-end vs the C daemon without USB |
| usbll state machine (SYN/null/rst, workarounds, odd-length rule, recovery matching) | real timing and firmware SYN contents | as pure logic: unit tests and recorded packet traces; no C seam without USB (optionally a C harness around `transport_usb.c`) |
| USB enumeration, claim, bulk I/O, timeouts, unplug/replug recovery, MTU | yes | Linux `dummy_hcd` + gadgetfs running the device build would emulate it but needs privileged module loading [H]; not possible on macOS |
| Real command semantics (`run`, `open tty://`, `get/put`, `connect`), `req:auth`, device password | yes | the device-side C (`src/device`, `commands_device.c`) could be built as a Linux fake peer over inet [H: needs nyx stubs] |

`transport_inet` is the key seam: it is a real, symmetric transport (host listens on 6969 and can also connect out with `-c`), and the emulator uses it. A fake device over TCP exercises everything above the link layer with the unmodified C host daemon.

## 8. Proposed Rust design and first slice

### 8.1 Module map (single crate `rovacomd`, edition 2024, std threads, no async)

| Rust module | Ports | Shared / platform |
|---|---|---|
| `cli.rs` | `getnextopt`, `handleopt`, `parse_commandline`, `usage`, getopt emulation and diagnostics | shared; diagnostic text by `cfg(target_os)` (P10) |
| `log.rs` | `log_printf` masks, timestamp, 256-byte truncation, stdout/stderr split, log socket fan-out | shared; `log/syslog` adapter `cfg(target_os = "linux")` (P8) |
| `net.rs` | `create_listen_socket`, `accept_socket`, `get_socket_port` | shared (std + `libc` for `SO_REUSEADDR` order, `FD_CLOEXEC`, `SO_RCVLOWAT`, `TCP_QUICKACK`) |
| `server.rs` | `main_loop`, socketchan, unblock, opt port, squelch | shared; `poll` instead of `select` (P5) |
| `devices.rs` | `active_device` registry, `dump_device_list`, `removedup`, refcounts | shared, pure formatting testable |
| `bufq.rs`, `mux.rs` | `buf_queue.c`, `mux.c` (codec + channel state machine, clock injected) | shared, pure |
| `usbll.rs` | `transport_usb.c` HOST paths, `recovery.c` | shared, pure |
| `inet.rs` | `transport_inet.c` | shared |
| `cmdparse.rs`, `wirebuf.rs`, `cmdservice.rs`, `tokens.rs` | `commands.c`, `buffer.c`, `host/commands_service.c`, `tokenstorage.c` | shared; home lookup via `getpwuid_r` |
| `devcmd.rs` | host-reachable part of `commands_device.c`/`packet.c` | shared; pending Q2 |
| `usb/mod.rs` | `UsbBackend` trait: enumerate (VID/PID table from `device_list.c`, interface match), claim, bulk read/write with timeout | shared trait + `usb/linux.rs` and `usb/macos.rs` |
| `usb/linux.rs` | `usb-linux.c`: usbdevfs `USBDEVFS_CLAIMINTERFACE`/`USBDEVFS_BULK` via `libc::ioctl`, enumeration from `/dev/bus/usb` descriptors [H, equivalent of libusb-0.1] | Linux |
| `usb/macos.rs` | patched path: libusb-1.0 via `rusb` (same stack as the patched C reference) | macOS |
| `sys.rs` | `fork`/`setsid`/`umask`/`chdir` daemonize, `SIGPIPE` ignore, `geteuid` | unix, minor `cfg` |

Proposed dependencies (versions recorded when added): `libc` (MIT/Apache-2.0; syscalls above, all `unsafe` confined to `net.rs`, `sys.rs`, `usb/linux.rs`); `sha1` (RustCrypto, MIT/Apache-2.0, same as the client port; token hash); `rusb` (MIT, macOS only, dynamically links libusb-1.0 which is LGPL-2.1, needs Homebrew/MacPorts libusb at build and run time). Not proposed: tokio, clap, nix. Linux could also use `rusb` (non-root with udev rules) at the cost of a native dependency and a behavior change for the root check (Q3).

Proposed support (not verified): Linux glibc x86_64/aarch64 with usbdevfs; macOS 11+ arm64/x86_64 with libusb-1.0 ≥ 1.0.24 [H].

### 8.2 First slice: inet device registration and device list

Smallest end-to-end path through the real daemon structure, no USB, no mux data.

- **Scope**: full CLI (3.2) and exit paths (4.13); logging to console; listeners 6968/6970/6971/12311/64022 with the single-instance probe; inet listen on 6969 with the 48-byte syn, `go_online("tcp","emulator")`, idle keepalive frames, disconnect → `go_offline`; `removedup` for repeated nduids; device list on 6968; `list host://` and unknown commands on 6971; per-device listen socket created (accepting clients deferred to slice 2). Control channel object exists but carries no traffic.
- **Inputs**: argv; fake device TCP peer; TCP clients on 6968/6971.
- **Outputs**: stdout/stderr bytes (timestamps normalized), exit code, device list bytes, ctrl reply bytes, frames sent to the fake device.
- **Compatibility assertions** (same OS, C vs Rust): `-V`, `-h`, unknown/missing options, `-t 1/6/junk`, `-e/-s` caps, `Cannot start novacomd twice!` exit 0; empty list; list with 1 and 2 fake devices (newest first, port field = actual listen port, line `"<port> <nduid> tcp emulator\n"`); same nduid twice (duplicate removed); bad syn magic → peer closed, no device; peer EOF → device gone from list; keepalive `ELTSDIM\0` + `0u32` within 2 s; `list host://` returns the list and closes without `ok`; `bogus x://` closes without data; `login dev://x h` with no device → `invalid command\n\0`.
- **Test strategy**: Rust fake-device and client helpers (std only); differential harness that starts `reference/novacomd/build/novacomd` (as user, both OSes) and `rovacomd` in turn on the **same fixed ports** (tests serialized; refuse to run if any of the six ports is busy, like the client port's control tests); unit tests for log formatting, CLI parsing and list formatting. Normalize: timestamp prefix, host nduid (random), per-device port numbers. Linux: same as macOS (the test reference skips the root check). Pairings: each daemon (C, Rust; Rust also as `novacomd`) is driven by both clients (`~/projects/rovacom/reference/novacom/build-novacom/novacom` and the `rovacom` binary, also as `novacom`). **Device safety:** the C reference and rovacomd scan USB at start. The harness must refuse to run while a Palm USB device (vendor 0x0830) is attached, so no test can reach the Pre3.
- **Platform paths**: identical code on both OSes except getopt diagnostics, syslog (Linux), and `TCP_QUICKACK` (Linux).
- **Next slices**: (2) `bufq` + `mux` + per-device client relay via the fake inet device (open/ack/retransmit/close, squelch, binary data, large streams); (3) host command service + tokens (unit/harness level); (4) `usbll` + recovery as pure state machines with trace tests; (5) USB backends (Linux usbdevfs, macOS libusb) and read-only Pre3 sessions with per-action approval; (6) log port, opt port, daemonize, device-initiated commands (per Q2).

## 9. Validation environments and gaps

| | macOS | Linux |
|---|---|---|
| Host | `deepthought`, macOS 27.2 (26B123), arm64 (checked 2026-10-31) | `a010`, Ubuntu 26.10, x86_64 (from the client assessment, not re-checked) |
| Rust | 1.99.1 stable (checked) | 1.99.1 per client assessment |
| C reference daemon | built and run as user (9.1) | built and run as user (9.1) |
| Pre3 device | to be attached to macOS later; read-only, per-action approval | none |

Gaps: no hardware for any USB path on either OS; no Linux C reference run; no USB emulation; macOS C behavior comes from a patched, never-shipped build (the original Palm macOS daemon source is not in this repository).

### 9.1 Reference builds (executed 2026-10-31)

`scripts/build-reference.sh` builds the C host daemon without root or system packages: libusb 1.0.30 and libusb-compat 0.1.9 release tarballs (SHA-256 pinned) into `reference/deps/prefix`, then the host sources compiled with `cc` (the CMake build needs the unavailable webOS cmake modules). Flags beyond the CMake ones: `-std=gnu11` (GCC 15 defaults to C23, where the source's `typedef ... bool` fails), `-fcommon` (GCC 10+ rejects `t_recovery_queue`, defined in both `recovery.c` and `usb-linux.c`), `-DWEBOS_TARGET_MACHINE_IMPL_HOST=1`, `-DREFERENCE_NO_ROOT_CHECK=1`; `-lrt` is not needed.

| | macOS 27.2 arm64, Apple clang 21.0.0 | Ubuntu 26.10 x86_64 (a010), GCC 15.3.0 |
|---|---|---|
| Build | executed, passed | executed, passed (failed before `-std=gnu11` and `-fcommon`) |
| `-h` | not executed here (earlier macOS build: usage printed) | executed: usage printed, exit 0 |
| Runs as user | yes (macOS patch) | without the test patch: `need to run as super user to access usb`, no ports; with it: listens on 127.0.0.1:6968-6971, empty device list, exit at `timeout 3` |
| Device attached | none | none |

## 10. Open questions that block correctness

1. **Q1 Pre3 USB identity and SYN.** Which VID/PID and interface descriptors does the Pre3 present (is it in `usbid_list`, e.g. Manta Ray `0x0830:0x805x`, or an HP `0x03F0` id?), and what does its firmware's SYN carry (`id:`, `sn:`, heartbeat/timeout, length)? Needs a read-only `ioreg`/`system_profiler` listing on the macOS host, with your approval, once it is attached.
2. **Q2 Device-initiated commands on the host (D1) and other unsafe defects.** Decided 2026-10-31 by the user: **keep D1 as C** (`get`/`put`/`connect` from a peer stay available on the host). Following that and the rovacom policy: deterministic defects are kept, including D2; memory-unsafe or undefined behavior (for example D14) cannot be reproduced in safe Rust and is changed to the nearest defined behavior, each listed as "intentionally changed".
3. **Q3 Linux privilege model and USB backend** (open; needed before slice 5, which brings USB and the root check; slices 1-4 have no USB code and so no root check). Keep the C rule "exit 1 unless euid 0" with raw usbdevfs, or use libusb-1.0 and allow non-root? (The test reference question is settled: `novacomd-test-noroot.patch`, Section 9.1.)
Assumed, following the rovacom client port (change only if you disagree):

4. **Q4 Fixed ports in tests.** Serialized tests on the fixed C ports, refusing to run if any port is busy (the client port's 6971 guard). No test-only port option.
5. **Q5 Program-name strings.** Text C derives from `argv[0]` follows `argv[0]`; fixed strings (`novacomd version …`, `Cannot start novacomd twice!`, syslog ident) stay verbatim, so `rovacomd` and `novacomd` print the same. `BUILDVERSION` default: `rovacomd-<crate version>`.
6. **Q6 Source-position text in logs.** Reproduce the upstream (unpatched) function names, `__FILE__` and `__LINE__` values verbatim, as rovacom does for `src/tcprelay.c:<line>`.
7. **Q7 macOS reference.** The libusb-compat build is the macOS reference for the USB side; it is the only one available. Its USB behavior is labeled "reference-patched", not "verified against Palm's macOS daemon".
