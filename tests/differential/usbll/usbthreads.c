/*
 * C driver of the USB thread harness (tests/differential/usbll.rs): the
 * rx and tx threads of a claimed device, run one at a time on the main
 * thread.
 *
 * Usage: usbthreads   (script on stdin, transcript on stdout)
 *
 * Includes driver.c (its stubs and hooks; its main renamed) and the
 * reference host/usb-linux.c as built (the working copy with the macOS
 * build patch: libusb-0.1 bulk calls on macOS, the usbdevfs ioctl on
 * Linux). Bulk transfers, usleep and the libusb-0.1 calls are stubbed;
 * transport_usb.c, recovery.c, mux.c (renamed as in driver.c),
 * buf_queue.c and device_list.c are linked unmodified.
 *
 * Script lines (byte fields hex encoded):
 *   N, T, W, M                as in driver.c
 *   E <timeout> <delay>       g_usbio_retry_timeout, g_usbio_retry_delay
 *   RD <cost> <bytes>         next read returns these bytes after <cost> ms
 *   RF <cost> <errno>         next read fails after <cost> ms
 *   WO                        next write succeeds
 *   WF <errno>                next write fails
 *   RX <bus> <dev> <devtype>  run novacom_usb_rx_thread on a new handle
 *                             (its tx thread counts as ended)
 *   TX <bus> <dev> <devtype> <syn>
 *                             run novacom_usb_tx_thread on a new handle
 *                             whose new link got <syn>
 *   Q                         number of recovery records
 * Unscripted reads fail with errno 110 after 10 ms, unscripted writes at
 * once with errno 32.
 * Output lines: as in driver.c, plus
 *   R <len> <timeout>         a read
 *   WR <timeout> <bytes>      a write
 *   SLEEP <ms>                usleep
 *   RXEND, TXEND, Q <n>
 */
#define HARNESS_THREADS 1
#define main usbll_driver_main
#include "driver.c"
#undef main
#include "host/usb-linux.c"

#include <stdarg.h>

#ifdef __linux__
#define FAILED(e) (-1)
#else
#define FAILED(e) (-(e))
#endif

static struct {
	int ok;
	unsigned int cost;
	int err;
	char *data;
	int len;
} rd[256];
static int nrd, next_rd;
static struct {
	int ok;
	int err;
} wr[256];
static int nwr, next_wr;

static int fake_read(void *buf, int len, int timeout)
{
	printf("R %d %d\n", len, timeout);
	if (next_rd >= nrd) {
		vclock += 10;
		errno = 110;
		return FAILED(110);
	}
	int i = next_rd++;
	vclock += rd[i].cost;
	if (!rd[i].ok) {
		errno = rd[i].err;
		return FAILED(rd[i].err);
	}
	memcpy(buf, rd[i].data, (size_t)rd[i].len);
	return rd[i].len;
}

static int fake_write(const void *buf, int len, int timeout)
{
	printf("WR %d ", timeout);
	put_hex(buf, (size_t)len);
	putchar('\n');
	int err = 32;
	if (next_wr < nwr) {
		int i = next_wr++;
		if (wr[i].ok)
			return len;
		err = wr[i].err;
	}
	errno = err;
	return FAILED(err);
}

#ifdef __linux__
int ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	struct usbdevfs_bulktransfer *b = va_arg(ap, struct usbdevfs_bulktransfer *);
	va_end(ap);
	(void)fd;
	if (b->ep & 0x80)
		return fake_read(b->data, (int)b->len, (int)b->timeout);
	return fake_write(b->data, (int)b->len, (int)b->timeout);
}
#else
int usb_bulk_read(usb_dev_handle *dev, int ep, char *bytes, int size, int timeout)
{
	(void)dev; (void)ep;
	return fake_read(bytes, size, timeout);
}

int usb_bulk_write(usb_dev_handle *dev, int ep, const char *bytes, int size, int timeout)
{
	(void)dev; (void)ep;
	return fake_write(bytes, size, timeout);
}
#endif

int usleep(useconds_t us)
{
	printf("SLEEP %u\n", (unsigned int)(us / 1000));
	vclock += us / 1000;
	return 0;
}

/* libusb-0.1 calls of the parts of usb-linux.c that are not run. */
void usb_init(void) {}
int usb_find_busses(void) { return 0; }
int usb_find_devices(void) { return 0; }
struct usb_bus *usb_get_busses(void) { return NULL; }
usb_dev_handle *usb_open(struct usb_device *dev) { (void)dev; return NULL; }
int usb_close(usb_dev_handle *dev) { (void)dev; return 0; }
int usb_claim_interface(usb_dev_handle *dev, int i) { (void)dev; (void)i; return 0; }
int usb_release_interface(usb_dev_handle *dev, int i) { (void)dev; (void)i; return 0; }
struct usb_device *usb_device(usb_dev_handle *dev) { (void)dev; return NULL; }
int platform_create_thread(platform_thread_t *t, thread_routine r, void *arg)
{
	(void)t; (void)r; (void)arg;
	return 0;
}
int platform_waitfor_thread(platform_thread_t t) { (void)t; return 0; }

static struct myusb_dev_handle fake_fd = { -1 };

static novacom_usb_handle_t *new_handle(int bus, int dev, const char *devtype)
{
	novacom_usb_handle_t *h = platform_calloc(sizeof(*h));
	h->myhandle = &fake_fd;
	h->rxep = 0x81;
	h->txep = 0x02;
	h->devtype = devtype;
	h->busnum = bus;
	h->devnum = dev;
	h->iface = -1;
	h->tx_startup_wait = 1;
	return h;
}

int main(void)
{
	static char line[4 * BUF_SIZE];
	static char devtypes[64][64];
	int ndevtypes = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	usbrecords_init();

	while (fgets(line, sizeof(line), stdin)) {
		char *rest = NULL;
		char *op = strtok_r(line, " \n", &rest);
		if (!op)
			continue;
		if (!strcmp(op, "N")) {
			sessionids[nsessionids++] = (uint32_t)strtoul(strtok_r(NULL, " \n", &rest), NULL, 16);
		} else if (!strcmp(op, "T")) {
			vclock = strtoull(strtok_r(NULL, " \n", &rest), NULL, 10);
		} else if (!strcmp(op, "W")) {
			g_recovery_timeout = atoi(strtok_r(NULL, " \n", &rest));
		} else if (!strcmp(op, "E")) {
			g_usbio_retry_timeout = atoi(strtok_r(NULL, " \n", &rest));
			g_usbio_retry_delay = atoi(strtok_r(NULL, " \n", &rest));
		} else if (!strcmp(op, "M")) {
			char *f = strtok_r(NULL, " \n", &rest);
			char *b = malloc(BUF_SIZE);
			size_t n = unhex(f, b, BUF_SIZE);
			mux_queue[nmux] = n ? b : NULL;
			mux_len[nmux++] = (int)n;
		} else if (!strcmp(op, "RD") || !strcmp(op, "RF")) {
			rd[nrd].ok = op[1] == 'D';
			rd[nrd].cost = (unsigned int)atoi(strtok_r(NULL, " \n", &rest));
			char *f = strtok_r(NULL, " \n", &rest);
			if (rd[nrd].ok) {
				rd[nrd].data = malloc(BUF_SIZE);
				rd[nrd].len = (int)unhex(f, rd[nrd].data, BUF_SIZE);
			} else {
				rd[nrd].err = atoi(f);
			}
			nrd++;
		} else if (!strcmp(op, "WO")) {
			wr[nwr++].ok = 1;
		} else if (!strcmp(op, "WF")) {
			wr[nwr].ok = 0;
			wr[nwr++].err = atoi(strtok_r(NULL, " \n", &rest));
		} else if (!strcmp(op, "RX") || !strcmp(op, "TX")) {
			int bus = atoi(strtok_r(NULL, " \n", &rest));
			int dev = atoi(strtok_r(NULL, " \n", &rest));
			char *dt = devtypes[ndevtypes++];
			size_t n = unhex(strtok_r(NULL, " \n", &rest), dt, 63);
			dt[n] = 0;
			novacom_usb_handle_t *h = new_handle(bus, dev, dt);
			if (op[0] == 'R') {
				novacom_usb_rx_thread(h);
				printf("RXEND\n");
			} else {
				static char syn[BUF_SIZE];
				size_t len = unhex(strtok_r(NULL, " \n", &rest), syn, BUF_SIZE);
				h->usbll_handle = novacom_usbll_create(dt, MAX_MTU, 0, USBDEVFS_IOCTL_TIMEOUT);
				novacom_usbll_setuid(h->usbll_handle, ((bus & 0xffff) << 16) | (dev & 0xffff));
				novacom_usbll_process_packet(h->usbll_handle, syn, (unsigned int)len);
				novacom_usb_tx_thread(h);
				printf("TXEND\n");
			}
		} else if (!strcmp(op, "Q")) {
			int n = 0;
			recovery_entry_t *item;
			TAILQ_FOREACH(item, &t_recovery_queue, entries)
				n++;
			printf("Q %d\n", n);
		} else {
			fprintf(stderr, "harness: bad line %s\n", op);
			return 4;
		}
	}
	return 0;
}
