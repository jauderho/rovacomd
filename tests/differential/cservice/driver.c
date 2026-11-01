/*
 * C driver of the command-service harness (tests/differential/cservice.rs).
 *
 * Usage: driver <home>   (script on stdin, transcript on stdout)
 *
 * Includes the unmodified reference main.c (its static functions
 * novacom_register_command, socketcmd_read_callback, ... are needed) with
 * main renamed, and links commands_service.c, tokenstorage.c, buffer.c,
 * sha1.c, commands.c and stubs.c. <home> replaces the passwd home
 * directory (stubs.c getpwuid).
 *
 * Script lines (fields hex encoded):
 *   D <devid> <sessionid>  register a USB device (index 0, 1, ...), then
 *                          run its init thread
 *   C <command>            a control client (index 0, 1, ...) sends the
 *                          command; the main-loop rule "close unless
 *                          queued" follows
 *   R <dev> <data>         the device replies on channel 0x50
 *   U <dev>                the device is unregistered
 * At EOF: one line per client, "K <client> <received hex> open|closed".
 * Events: "O <dev> <channel> <command>" (channel open),
 *         "W <dev> <channel> <hex>" (channel write).
 */
#define main novacomd_main
#include "main.c"
#undef main
#undef malloc
#undef calloc
#undef realloc
#undef free
#undef printf
#undef fprintf

#include <fcntl.h>

extern const char *harness_home;
extern int harness_getpwuid_calls;
extern thread_routine harness_thread_fn;
extern void *harness_thread_arg;
typedef int (*harness_read_callback)(void *, uint32_t, int, const void *, size_t, void *);
extern harness_read_callback harness_read_cb[];
extern void *harness_read_cookie[];
extern void harness_device_offline(void *dev);

#define MAX_CLIENTS 64

static size_t unhex(const char *s, char *out)
{
	size_t n = 0;
	unsigned int b;
	while (s[0] && s[1] && sscanf(s, "%2x", &b) == 1) {
		out[n++] = (char)b;
		s += 2;
	}
	out[n] = 0;
	return n;
}

int main(int argc, char **argv)
{
	char line[4096], a[2048], b[2048];
	int clients[MAX_CLIENTS];
	int nclients = 0;
	intptr_t ndevs = 0;

	if (argc != 2)
		return 2;
	harness_home = argv[1];
	setvbuf(stdout, NULL, _IONBF, 0);
	platform_mutex_init(&device_list_mutex);

	while (fgets(line, sizeof(line), stdin)) {
		char *f1 = strtok(line + 1, " \n");
		char *f2 = strtok(NULL, " \n");
		switch (line[0]) {
		case 'D': {
			novacom_device_reginfo_t ri;
			memset(&ri, 0, sizeof(ri));
			unhex(f1 ? f1 : "", a);
			unhex(f2 ? f2 : "", b);
			ri.devid_string = a;
			ri.conntype = "usb";
			ri.devtype = "castle-linux";
			ri.devmode = "";
			ri.sessionid = b;
			novacom_register_device((device_handle_t)(ndevs + 1), &ri);
			ndevs++;
			if (harness_thread_fn) {
				thread_routine fn = harness_thread_fn;
				harness_thread_fn = NULL;
				fn(harness_thread_arg);
			}
			break;
		}
		case 'C': {
			int sv[2];
			size_t n = unhex(f1 ? f1 : "", a);
			if (nclients == MAX_CLIENTS || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
				return 3;
			if (write(sv[1], a, n) != (ssize_t)n)
				return 3;
			clients[nclients++] = sv[1];
			if (novacom_register_command(sv[0], NULL))
				close(sv[0]);
			break;
		}
		case 'R': {
			int i = atoi(f1 ? f1 : "0");
			size_t n = unhex(f2 ? f2 : "", a);
			if (harness_read_cb[i])
				harness_read_cb[i]((void *)(intptr_t)(i + 1), PMUX_CHANNEL_CMDSERVICE, 0, a, n, harness_read_cookie[i]);
			break;
		}
		case 'U': {
			intptr_t i = atoi(f1 ? f1 : "0");
			novacom_unregister_device((device_handle_t)(i + 1));
			harness_device_offline((void *)(i + 1));
			break;
		}
		default:
			return 4;
		}
	}

	for (int k = 0; k < nclients; k++) {
		unsigned char buf[512];
		ssize_t r;
		const char *state = "open";
		fcntl(clients[k], F_SETFL, O_NONBLOCK);
		printf("K %d ", k);
		for (;;) {
			r = read(clients[k], buf, sizeof(buf));
			if (r <= 0) {
				if (r == 0)
					state = "closed";
				break;
			}
			for (ssize_t j = 0; j < r; j++)
				printf("%02x", buf[j]);
		}
		printf(" %s\n", state);
	}
	fprintf(stderr, "getpwuid calls: %d\n", harness_getpwuid_calls);
	return 0;
}
