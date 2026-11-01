/*
 * Stubs for the C command-service harness (tests/differential/cservice.rs).
 *
 * They replace the daemon parts that the unmodified main.c,
 * commands_service.c, tokenstorage.c, buffer.c, sha1.c and commands.c call
 * but that the harness does not exercise: platform, logging, sockets,
 * transports and the mux. The mux stubs record channel opens and writes
 * on stdout (see driver.c). getpwuid and connect are defined here so that
 * they take precedence over libc at link time: the token directory is the
 * temp home given to the driver, and unblock_main_loop never reaches port
 * 12311.
 *
 * This file does not include platform.h (which renames malloc and friends).
 */
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/* --- isolation ----------------------------------------------------------- */

const char *harness_home; /* set by driver.c before anything else runs */
int harness_getpwuid_calls;

struct passwd *getpwuid(uid_t uid)
{
	static struct passwd pw;
	(void)uid;
	harness_getpwuid_calls++;
	memset(&pw, 0, sizeof(pw));
	pw.pw_name = "harness";
	pw.pw_dir = (char *)harness_home;
	return &pw;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	(void)fd; (void)addr; (void)len;
	errno = ECONNREFUSED;
	return -1;
}

/* --- platform ------------------------------------------------------------ */

typedef void *(*thread_routine)(void *);

/* One deferred thread: driver.c runs it after novacom_register_device
 * returns (as the C thread first waits for the mux lock that
 * novacom_go_online holds during registration). */
thread_routine harness_thread_fn;
void *harness_thread_arg;

int platform_create_thread(void *thread, thread_routine routine, void *arg)
{
	(void)thread;
	if (harness_thread_fn) {
		fprintf(stderr, "harness: more than one pending thread\n");
		abort();
	}
	harness_thread_fn = routine;
	harness_thread_arg = arg;
	return 0;
}

void *platform_alloc(size_t len) { return malloc(len); }
void *platform_calloc(size_t len) { return calloc(1, len); }
void *platform_realloc(void *p, size_t len) { return realloc(p, len); }
void platform_free(void *p) { free(p); }
char *platform_strdup(const char *s) { return strdup(s); }
void platform_init(void) {}
void platform_abort(void) { abort(); }
int platform_socket_getlasterrno(void) { return errno; }
/* Single-threaded harness: the locks are no-ops. */
int platform_mutex_init(void *m) { (void)m; return 0; }
void platform_mutex_lock(void *m) { (void)m; }
void platform_mutex_unlock(void *m) { (void)m; }
int platform_atomic_add(volatile int *val, int inc)
{
	int old = *val;
	*val += inc;
	return old;
}

/* --- logging, sockets, transports: unused by the harness ------------------ */

void log_printf(unsigned int mask, const char *fmt, ...) { (void)mask; (void)fmt; }
void log_init(void) {}
void log_mask(unsigned int output, unsigned int mask) { (void)output; (void)mask; }
void log_add_socket(int s) { (void)s; }
int create_listen_socket(int port, int bindall) { (void)port; (void)bindall; return -1; }
int accept_socket(int s) { (void)s; return -1; }
int get_socket_port(int fd) { (void)fd; return 0; }
int recv_socket(int fd, char *buf, size_t len, int flags)
{
	(void)fd; (void)buf; (void)len; (void)flags;
	return -1;
}
void inetconnect_connect_to(char *host, char *serv) { (void)host; (void)serv; }
int transport_init(void) { return 0; }
int transport_start(void) { return 0; }
int novacom_init(void) { return 0; }

/* --- mux ----------------------------------------------------------------- */

/* Device handles are (void *)(index + 1). */
#define HARNESS_MAX_DEVICES 16
static int opened[HARNESS_MAX_DEVICES];
typedef int (*read_callback)(void *dev, uint32_t channel, int err, const void *buf, size_t len, void *cookie);
read_callback harness_read_cb[HARNESS_MAX_DEVICES];
void *harness_read_cookie[HARNESS_MAX_DEVICES];

static int dev_index(void *dev)
{
	intptr_t i = (intptr_t)dev - 1;
	if (i < 0 || i >= HARNESS_MAX_DEVICES) {
		fprintf(stderr, "harness: bad device handle\n");
		abort();
	}
	return (int)i;
}

void harness_device_offline(void *dev) { opened[dev_index(dev)] = 0; }

int novacom_open_channel(void *dev, uint32_t num, int command)
{
	int i = dev_index(dev);
	printf("O %d %x %d\n", i, num, command);
	opened[i] = 1;
	return 0;
}

int novacom_set_read_callback(void *dev, uint32_t chan, read_callback cb, void *cookie)
{
	int i = dev_index(dev);
	(void)chan;
	harness_read_cb[i] = cb;
	harness_read_cookie[i] = cookie;
	return 0;
}

int novacom_write_channel_async(void *dev, uint32_t chan, const void *buf, size_t len, unsigned int flags, void *cb, void *cookie)
{
	int i = dev_index(dev);
	(void)flags; (void)cb; (void)cookie;
	if (!opened[i])
		return -1;
	printf("W %d %x ", i, chan);
	for (size_t k = 0; k < len; k++)
		printf("%02x", ((const unsigned char *)buf)[k]);
	printf("\n");
	return 0;
}

int novacom_open_temp_channel(void *dev, uint32_t *chan, int command) { (void)dev; (void)chan; (void)command; return -1; }
int novacom_close_channel(void *dev, uint32_t chan) { (void)dev; (void)chan; return -1; }
size_t novacom_tx_queue_len(void *dev, uint32_t chan) { (void)dev; (void)chan; return 0; }
void novacom_retain_device_handle(void *dev) { (void)dev; }
void novacom_release_device_handle(void *dev) { (void)dev; }
