#!/usr/bin/env bash
#
# build-reference.sh - Build the original C novacomd (host flavor) as a test
# reference, without root and without system packages.
#
# Steps, all under reference/ (gitignored):
#   1. Download libusb 1.0.30 and libusb-compat 0.1.9 release tarballs from
#      GitHub and check their SHA-256 digests.
#   2. Build libusb-1.0 (configure/make) and libusb-0.1 (libusb-compat
#      core.c compiled directly, without its exit-time destructor; its
#      configure needs pkg-config macros) into reference/deps/prefix.
#   3. Clone openwebos/novacomd at the pinned commit into
#      reference/novacomd, apply scripts/patches/novacomd-macos.patch (build
#      enablement only; on Linux it changes nothing) and
#      scripts/patches/novacomd-test-noroot.patch (test enablement: with
#      REFERENCE_NO_ROOT_CHECK, Linux skips the root check so the TCP side
#      runs without root), and compile the host sources with cc (the
#      upstream CMake build needs the webOS cmake modules). Output:
#      reference/novacomd/build/novacomd
#
# Usage:
#   scripts/build-reference.sh [--dryrun] [--verbose] [--clean] [--help]
#
# Options:
#   --dryrun    Print the actions without running them.
#   -v, --verbose
#               Print each step and key variables.
#   --clean     Remove reference/ before building.
#   -h, --help  Print this help and exit.
#
# Environment:
#   NO_COLOR    Disable colored output when set.

set -euo pipefail

readonly REPO_URL="https://github.com/openwebos/novacomd.git"
readonly PINNED_COMMIT="530a10378af854fc0723b14f3f807d26a028070d"
readonly BUILD_VERSION="ref-530a103"
readonly LIBUSB_URL="https://github.com/libusb/libusb/releases/download/v1.0.30/libusb-1.0.30.tar.bz2"
readonly LIBUSB_SHA256="fea36f34f9156400209595e300840767ab1a385ede1dc7ee893015aea9c6dbaf"
readonly COMPAT_URL="https://github.com/libusb/libusb-compat-0.1/releases/download/v0.1.9/libusb-compat-0.1.9.tar.bz2"
readonly COMPAT_SHA256="179d934676ad3bd172a5a37cf5c6351b8e9d7816feb3029252e79b30a518a3be"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly REF="${ROOT}/reference"
readonly DEPS="${REF}/deps"
readonly PREFIX="${DEPS}/prefix"
readonly SRC_DIR="${REF}/novacomd"
readonly PATCHES=("${ROOT}/scripts/patches/novacomd-macos.patch" "${ROOT}/scripts/patches/novacomd-test-noroot.patch")

dryrun=0
verbose=0
clean=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	C_RED=$'\033[31m' C_GRN=$'\033[32m' C_DIM=$'\033[2m' C_OFF=$'\033[0m'
else
	C_RED="" C_GRN="" C_DIM="" C_OFF=""
fi

log() { if ((verbose)); then printf '%s%s%s\n' "${C_DIM}" "$*" "${C_OFF}"; fi; }
die() {
	printf '%serror:%s %s\n' "${C_RED}" "${C_OFF}" "$*" >&2
	exit 1
}
run() {
	if ((dryrun)); then
		printf 'dryrun: %s\n' "$*"
	else
		log "+ $*"
		"$@"
	fi
}
usage() { sed -n '3,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while (($#)); do
	case "$1" in
	--dryrun) dryrun=1 ;;
	-v | --verbose) verbose=1 ;;
	--clean) clean=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1" ;;
	esac
	shift
done

for tool in git make cc curl tar; do
	command -v "${tool}" >/dev/null || die "${tool} not found"
done

case "$(uname -s)" in
Darwin)
	so_ext="dylib"
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
	;;
Linux)
	so_ext="so"
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
	;;
*) die "unsupported OS: $(uname -s)" ;;
esac
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

log "root=${ROOT} commit=${PINNED_COMMIT} os=$(uname -s) jobs=${jobs}"

if ((clean)); then
	run rm -rf "${REF}"
fi

# fetch URL SHA256: downloads into deps/dl once and checks the digest.
fetch() {
	local url="$1" want="$2" file
	file="${DEPS}/dl/$(basename "${url}")"
	if [[ ! -f "${file}" ]]; then
		run mkdir -p "${DEPS}/dl"
		run curl --proto '=https' --tlsv1.2 -fsSL -o "${file}" "${url}"
	fi
	if ((! dryrun)); then
		local got
		got="$(sha256 "${file}")"
		[[ "${got}" == "${want}" ]] || die "$(basename "${file}"): sha256 ${got}, expected ${want}"
	fi
}

if [[ ! -f "${PREFIX}/include/usb.h" ]]; then
	fetch "${LIBUSB_URL}" "${LIBUSB_SHA256}"
	fetch "${COMPAT_URL}" "${COMPAT_SHA256}"
	run rm -rf "${DEPS}/src"
	run mkdir -p "${DEPS}/src"
	run tar -xjf "${DEPS}/dl/libusb-1.0.30.tar.bz2" -C "${DEPS}/src"
	run tar -xjf "${DEPS}/dl/libusb-compat-0.1.9.tar.bz2" -C "${DEPS}/src"

	# libusb-1.0. Without udev, Linux enumerates devices via netlink.
	configure_args=(--prefix="${PREFIX}" --disable-static)
	if [[ "$(uname -s)" == Linux ]]; then
		configure_args+=(--disable-udev)
	fi
	(
		cd "${DEPS}/src/libusb-1.0.30"
		run ./configure -q "${configure_args[@]}"
		run make -s -j"${jobs}"
		run make -s install
	)

	# libusb-0.1 API on top of libusb-1.0: one source file. config.h only
	# needs the export macro.
	compat="${DEPS}/src/libusb-compat-0.1.9"
	# Remove the `_usb_exit` destructor: at `exit` it frees the bus list and
	# calls libusb_exit while novacomd's USB scan thread may still use them,
	# so the reference sometimes crashes (SIGSEGV or a usbi_mutex_lock
	# assertion) when it exits. libusb-0.1, which novacomd was built
	# against, has no such destructor.
	run sed -i.orig 's/static void __attribute__ ((destructor)) _usb_exit/static void _usb_exit/' "${compat}/libusb/core.c"
	if ((! dryrun)) && grep -q 'destructor' "${compat}/libusb/core.c"; then
		die "libusb-compat destructor not removed"
	fi
	if ((dryrun)); then
		printf 'dryrun: write %s/config.h\n' "${compat}"
	else
		printf '#define API_EXPORTED __attribute__((visibility("default")))\n' >"${compat}/config.h"
	fi
	run cc -O2 -fPIC -DENABLE_LOGGING=1 -I"${compat}" -I"${compat}/libusb" \
		-I"${PREFIX}/include/libusb-1.0" -c "${compat}/libusb/core.c" -o "${compat}/core.o"
	if [[ "${so_ext}" == dylib ]]; then
		run cc -dynamiclib -install_name "${PREFIX}/lib/libusb-0.1.4.dylib" \
			-o "${PREFIX}/lib/libusb-0.1.4.dylib" "${compat}/core.o" -L"${PREFIX}/lib" -lusb-1.0
		run ln -sf libusb-0.1.4.dylib "${PREFIX}/lib/libusb.dylib"
	else
		run cc -shared -Wl,-soname,libusb-0.1.so.4 -o "${PREFIX}/lib/libusb-0.1.so.4" \
			"${compat}/core.o" -L"${PREFIX}/lib" -lusb-1.0 -Wl,-rpath,"${PREFIX}/lib"
		run ln -sf libusb-0.1.so.4 "${PREFIX}/lib/libusb.so"
	fi
	run cp "${compat}/libusb/usb.h" "${PREFIX}/include/usb.h"
else
	log "deps already built in ${PREFIX}"
fi

if [[ ! -d "${SRC_DIR}/.git" ]]; then
	run mkdir -p "${REF}"
	run git clone --quiet "${REPO_URL}" "${SRC_DIR}"
fi
run git -C "${SRC_DIR}" checkout --quiet --force --detach "${PINNED_COMMIT}"
if ((! dryrun)); then
	head="$(git -C "${SRC_DIR}" rev-parse HEAD)"
	[[ "${head}" == "${PINNED_COMMIT}" ]] || die "checkout is ${head}, expected ${PINNED_COMMIT}"
fi
for patch in "${PATCHES[@]}"; do
	run git -C "${SRC_DIR}" apply "${patch}"
done

# Same sources and defines as the CMake host build (CMakeLists.txt, target
# machine "host"); -lrt is needed by glibc before 2.17 only, so it is left out.
# -std=gnu11: GCC 15 defaults to C23, where `bool` is a keyword and the
# source's `typedef ... bool` fails. -fcommon: GCC 10+ defaults to
# -fno-common, and the source defines `t_recovery_queue` in two files.
(
	cd "${SRC_DIR}"
	run mkdir -p build
	sources=(src/lib/*.c src/lib/cksum/*.c src/novacom/*.c src/host/*.c
		src/platform_pthreads.c src/main.c src/log.c src/socket.c
		src/transport.c src/transport_inet.c src/transport_usb.c)
	run cc -std=gnu11 -fcommon -O2 -g -Wall -DPLATFORM_PTHREADS=1 -DHOST=1 -DWEBOS_TARGET_MACHINE_IMPL_HOST=1 -DREFERENCE_NO_ROOT_CHECK=1 \
		"-DBUILDVERSION=\"${BUILD_VERSION}\"" -Iinclude -I"${PREFIX}/include" \
		"${sources[@]}" -L"${PREFIX}/lib" -lusb -lusb-1.0 -Wl,-rpath,"${PREFIX}/lib" \
		-lpthread -o build/novacomd
)

if ((! dryrun)); then
	[[ -x "${SRC_DIR}/build/novacomd" ]] || die "build produced no binary"
	printf '%sbuilt%s %s\n' "${C_GRN}" "${C_OFF}" "${SRC_DIR}/build/novacomd"
fi
