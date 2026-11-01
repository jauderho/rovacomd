/*
 * Stubs for the C USB link-layer harness (tests/differential/usbll.rs):
 * the platform functions that transport_usb.c, recovery.c, mux.c and
 * buf_queue.c call, for one thread. Logging, time, session ids and the
 * mux packet I/O are in driver.c.
 *
 * This file does not include platform.h (which renames malloc and friends).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *platform_alloc(size_t len) { return malloc(len); }
void *platform_calloc(size_t len) { return calloc(1, len); }
void *platform_realloc(void *p, size_t len) { return realloc(p, len); }
void platform_free(void *p) { free(p); }
char *platform_strdup(const char *s) { return strdup(s); }

/* platform_assert: the ASSERT FAILED line is logged first; C then crashes. */
void platform_abort(void)
{
	printf("ABORT\n");
	exit(0);
}

/* One thread: locks and events are no-ops. */
int platform_mutex_init(void *m) { (void)m; return 0; }
void platform_mutex_lock(void *m) { (void)m; }
void platform_mutex_unlock(void *m) { (void)m; }
void platform_mutex_destroy(void *m) { (void)m; }
int platform_event_create(void *e) { (void)e; return 0; }
void platform_event_destroy(void *e) { (void)e; }
void platform_event_signal(void *e) { (void)e; }
void platform_event_unsignal(void *e) { (void)e; }
void platform_event_wait(void *e) { (void)e; }
int platform_event_wait_timeout(void *e, long ms) { (void)e; (void)ms; return 0; }
int platform_atomic_add(volatile int *val, int inc)
{
	int old = *val;
	*val += inc;
	return old;
}

/* mux.c references these; the harness never reaches them. */
int log_would_log(unsigned int mask) { (void)mask; return 0; }
int novacom_setup_command(void *dev, uint32_t chan) { (void)dev; (void)chan; return -1; }
int novacom_unregister_device(void *dev) { (void)dev; return 0; }
