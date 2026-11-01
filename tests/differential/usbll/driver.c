/*
 * C driver of the USB link-layer harness (tests/differential/usbll.rs).
 *
 * Usage: driver   (script on stdin, transcript on stdout)
 *
 * With HARNESS_THREADS defined, usbthreads.c includes this file for its
 * stubs (main renamed): an empty mux queue then means "no packet within
 * the timeout" (the virtual clock advances by it).
 *
 * Includes the unmodified reference transport_usb.c (for the link state
 * printed by "G") and links the unmodified recovery.c, buf_queue.c and
 * mux.c (compiled with the mux calls of transport_usb.c renamed, so that
 * the real novacom_go_online registers devices while packet I/O goes to
 * the stubs below). Single-threaded; the clock is virtual.
 *
 * Script lines (byte fields hex encoded, "-" = none/empty):
 *   W <secs>                  g_recovery_timeout
 *   N <hex u32>               next novacom_get_new_sessionid() value
 *   T <ms>                    set the virtual clock
 *   C <devtype> <max_mtu> <heartbeat> <timeout>
 *                             novacom_usbll_create -> link 0, 1, ...
 *   I <link> <uid>            novacom_usbll_setuid
 *   X <link> <len> <bytes>    the bytes arrive in the link's receive
 *                             buffer (bytes past them keep older content);
 *                             header check, then process unless bad
 *   M <bytes|->               next novacom_get_tx_packet result
 *   S <link>                  novacom_usbll_prepare_tx_packet(link,
 *                             {tx buffer, get_mtu(link)}, 100)
 *   O <link>                  novacom_usbll_drop_offline
 *   Z <link>                  novacom_usbll_destroy
 *   G <link>                  print the link state
 *   A <link>                  park the link (the rx thread's cleanup)
 *   F <bytes>                 sniff: recovery token of these header bytes
 *                             (zero padded), usbrecords_find
 *   U <elapsed>               usbrecords_update
 *   R <nduid>                 usbrecords_remove
 * Output lines: the result of each step, plus
 *   L <mask> <text>           log_printf (text escaped)
 *   REG <dev> <nduid> <conntype> <devtype> <devmode> <sessionid>
 *   OFF <dev>                 novacom_go_offline
 *   PMUX <dev> <len> <bytes>  novacom_process_packet
 *   GETTX <dev> <timeout> <len>
 *   ABORT                     platform_abort (then exit 0)
 */
#include "transport_usb.c"
#undef malloc
#undef calloc
#undef realloc
#undef free
#undef printf
#undef fprintf

#include <stdarg.h>

#define MAX_LINKS 64
#define MAX_DEVS 64
#define BUF_SIZE 16384

int g_recovery_timeout = 5;
int g_usbio_retry_timeout = 100;
int g_usbio_retry_delay = 50;

static unsigned long long vclock;
static uint32_t sessionids[256];
static int nsessionids, next_sessionid;
static char *mux_queue[256];
static int mux_len[256];
static int nmux, next_mux;
static void *devs[MAX_DEVS];
static int ndevs;
static novacom_usbll_handle_t links[MAX_LINKS];
static int nlinks;
static char rxbuf[MAX_LINKS][BUF_SIZE];
static char txbuf[MAX_LINKS][BUF_SIZE];

static void put_escaped(const char *s, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c >= 0x20 && c < 0x7f && c != '\\')
			putchar(c);
		else
			printf("\\x%02x", c);
	}
}

static void put_hex(const char *s, size_t n)
{
	if (n == 0)
		putchar('-');
	for (size_t i = 0; i < n; i++)
		printf("%02x", (unsigned char)s[i]);
}

static size_t unhex(const char *s, char *out, size_t max)
{
	size_t n = 0;
	unsigned int b;
	if (strcmp(s, "-") == 0)
		return 0;
	while (s[0] && s[1] && n < max && sscanf(s, "%2x", &b) == 1) {
		out[n++] = (char)b;
		s += 2;
	}
	return n;
}

static int dev_index(void *dev)
{
	for (int i = 0; i < ndevs; i++)
		if (devs[i] == dev)
			return i;
	return -1;
}

static int link_index(void *link)
{
	for (int i = 0; i < nlinks; i++)
		if ((void *)links[i] == link)
			return i;
	return -1;
}

/* --- platform and lib --------------------------------------------------- */

void platform_get_time(platform_time_t *t)
{
	t->time.tv_sec = (time_t)(vclock / 1000);
	t->time.tv_usec = (suseconds_t)((vclock % 1000) * 1000);
}

/* Same formula as platform_pthreads.c. */
int platform_delta_time_msecs(const platform_time_t *a, const platform_time_t *b)
{
	uint64_t atime, btime;

	atime = a->time.tv_sec * 1000000 + a->time.tv_usec;
	btime = b->time.tv_sec * 1000000 + b->time.tv_usec;

	return (btime - atime) / 1000;
}

void log_printf(unsigned int mask, const char *fmt, ...)
{
	char msg[4096];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (n < 0)
		n = 0;
	if (n >= (int)sizeof(msg))
		n = sizeof(msg) - 1;
	printf("L %u ", mask);
	put_escaped(msg, (size_t)n);
	putchar('\n');
}

uint32_t novacom_get_new_sessionid()
{
	if (next_sessionid >= nsessionids) {
		fprintf(stderr, "harness: no session id left\n");
		exit(5);
	}
	return sessionids[next_sessionid++];
}

const char *novacom_nduid(void)
{
	static char id[] = "0123456789abcdef0123456789abcdef01234567";
	return id;
}

/* --- device registry and mux packet I/O ---------------------------------- */

void novacom_register_device(device_handle_t mux, novacom_device_reginfo_t *ri)
{
	if (ndevs == MAX_DEVS)
		exit(6);
	devs[ndevs] = mux;
	printf("REG %d ", ndevs++);
	put_hex(ri->devid_string, strlen(ri->devid_string));
	printf(" %s ", ri->conntype);
	put_hex(ri->devtype, strlen(ri->devtype));
	putchar(' ');
	put_hex(ri->devmode, strlen(ri->devmode));
	putchar(' ');
	put_hex(ri->sessionid, strlen(ri->sessionid));
	putchar('\n');
}

void novacom_go_offline(device_handle_t dev)
{
	printf("OFF %d\n", dev_index(dev));
}

void novacom_retain_device_handle(device_handle_t dev) { (void)dev; }
void novacom_release_device_handle(device_handle_t dev) { (void)dev; }

int novacom_process_packet(device_handle_t dev, const char *buf, int len)
{
	printf("PMUX %d %d ", dev_index(dev), len);
	put_hex(buf, (size_t)len);
	putchar('\n');
	return PACKET_TYPE_DATA;
}

/* Like the C mux, the packet is written without its pad byte (index 5). */
static int next_tx_packet(device_handle_t dev, struct novacom_tx_packet *packet, int timeout)
{
	printf("GETTX %d %d %d\n", dev_index(dev), timeout, (int)packet->len);
	if (next_mux >= nmux) {
#ifdef HARNESS_THREADS
		/* Nothing queued: the mux waits out the timeout. */
		vclock += (unsigned long long)timeout;
		return TX_NO_PACKET;
#else
		fprintf(stderr, "harness: no mux packet scripted\n");
		exit(7);
#endif
	}
	char *p = mux_queue[next_mux];
	int n = mux_len[next_mux++];
	if (!p)
		return TX_NO_PACKET;
	for (int i = 0; i < n; i++)
		if (i != 5)
			packet->buf[i] = p[i];
	packet->len = n;
	return 0;
}

int novacom_get_tx_packet(device_handle_t dev, struct novacom_tx_packet *packet, int timeout)
{
	return next_tx_packet(dev, packet, timeout);
}

int novacom_prepare_tx_packet(device_handle_t dev, struct novacom_tx_packet *packet)
{
	return next_tx_packet(dev, packet, -1);
}

#ifndef HARNESS_THREADS
/* usb-linux.c (linked by the thread harness) has the real one. */
int novacom_usb_transport_deviceonline(char *nduid)
{
	usbrecords_remove(nduid);
	return 0;
}
#endif

/* --- script ------------------------------------------------------------- */

static void print_state(int k)
{
	novacom_usbll_handle_t h = links[k];
	printf("G %d %d %08x %08x %d %08x %08x %u %u %d %d %d ", k, h->state, h->sessionid,
		h->remoteid, h->nextcommand, h->reset_sessionid, h->reset_remoteid, h->max_mtu,
		h->mtu, h->heartbeat_interval, h->timeout, h->device_handle != NULL);
	put_hex(h->remote_nduid, strlen(h->remote_nduid));
	printf(" %d ", h->synpacket_size);
	if (h->recovery_token)
		printf("%08x:%08x", h->recovery_token->txid, h->recovery_token->rxid);
	else
		putchar('-');
	printf(" %08x\n", h->uid);
}

int main(void)
{
	static char line[4 * BUF_SIZE];
	static char bytes[BUF_SIZE];
	char f[4][64];

	setvbuf(stdout, NULL, _IONBF, 0);
	usbrecords_init();

	while (fgets(line, sizeof(line), stdin)) {
		char *rest = NULL;
		char *op = strtok_r(line, " \n", &rest);
		if (!op)
			continue;
		switch (op[0]) {
		case 'W':
			g_recovery_timeout = atoi(strtok_r(NULL, " \n", &rest));
			break;
		case 'N':
			sessionids[nsessionids++] = (uint32_t)strtoul(strtok_r(NULL, " \n", &rest), NULL, 16);
			break;
		case 'T':
			vclock = strtoull(strtok_r(NULL, " \n", &rest), NULL, 10);
			break;
		case 'C': {
			for (int i = 0; i < 4; i++)
				snprintf(f[i], sizeof(f[i]), "%s", strtok_r(NULL, " \n", &rest));
			static char devtype[MAX_LINKS][64];
			size_t n = unhex(f[0], devtype[nlinks], 63);
			devtype[nlinks][n] = 0;
			links[nlinks] = novacom_usbll_create(devtype[nlinks], (uint32_t)strtoul(f[1], NULL, 10),
				atoi(f[2]), atoi(f[3]));
			printf("C %d\n", nlinks++);
			break;
		}
		case 'I': {
			int k = atoi(strtok_r(NULL, " \n", &rest));
			novacom_usbll_setuid(links[k], (uint32_t)strtoul(strtok_r(NULL, " \n", &rest), NULL, 10));
			break;
		}
		case 'X': {
			int k = atoi(strtok_r(NULL, " \n", &rest));
			unsigned int len = (unsigned int)atoi(strtok_r(NULL, " \n", &rest));
			unhex(strtok_r(NULL, " \n", &rest), rxbuf[k], BUF_SIZE);
			if (novacom_usbll_check_packet_header(rxbuf[k], len)) {
				printf("X %d bad\n", k);
			} else {
				int t = novacom_usbll_process_packet(links[k], rxbuf[k], len);
				printf("X %d %d\n", k, t);
			}
			break;
		}
		case 'M': {
			size_t n = unhex(strtok_r(NULL, " \n", &rest), bytes, BUF_SIZE);
			if (n == 0) {
				mux_queue[nmux] = NULL;
			} else {
				mux_queue[nmux] = malloc(n);
				memcpy(mux_queue[nmux], bytes, n);
			}
			mux_len[nmux++] = (int)n;
			break;
		}
		case 'S': {
			int k = atoi(strtok_r(NULL, " \n", &rest));
			struct novacom_tx_packet packet;
			packet.buf = txbuf[k];
			packet.len = novacom_usbll_get_mtu(links[k]);
			int ret = novacom_usbll_prepare_tx_packet(links[k], &packet, 100);
			printf("S %d %d ", k, ret);
			if (ret >= 0)
				put_hex(packet.buf, packet.len);
			else
				putchar('-');
			putchar('\n');
			break;
		}
		case 'O':
			novacom_usbll_drop_offline(links[atoi(strtok_r(NULL, " \n", &rest))]);
			break;
		case 'Z':
			novacom_usbll_destroy(links[atoi(strtok_r(NULL, " \n", &rest))]);
			break;
		case 'G':
			print_state(atoi(strtok_r(NULL, " \n", &rest)));
			break;
		case 'A': {
			int k = atoi(strtok_r(NULL, " \n", &rest));
			transport_recovery_token_t *rec = platform_calloc(sizeof(*rec));
			snprintf(rec->nduid, sizeof(rec->nduid), "%s", novacom_usbll_get_nduid(links[k]));
			int rc = novacom_usbll_get_recovery_token(links[k], rec);
			if (rc != -1)
				rc = usbrecords_add(rec);
			if (rc == -1) {
				novacom_usbll_destroy(links[k]);
				platform_free(rec);
			}
			printf("A %d %d\n", k, rc);
			break;
		}
		case 'F': {
			memset(bytes, 0, 64);
			unhex(strtok_r(NULL, " \n", &rest), bytes, 64);
			transport_recovery_token_t sniff;
			novacom_usbll_generate_recovery_token(bytes, 20, &sniff);
			int ret = usbrecords_find(&sniff);
			platform_free(sniff.token);
			printf("F %d\n", ret ? -1 : link_index(sniff.user_data));
			break;
		}
		case 'U':
			usbrecords_update(atoi(strtok_r(NULL, " \n", &rest)));
			break;
		case 'R': {
			size_t n = unhex(strtok_r(NULL, " \n", &rest), bytes, 64);
			bytes[n] = 0;
			usbrecords_remove(bytes);
			break;
		}
		default:
			fprintf(stderr, "harness: bad line %s\n", op);
			return 4;
		}
	}
	return 0;
}
