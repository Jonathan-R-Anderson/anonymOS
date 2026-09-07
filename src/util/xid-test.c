// xid-test.c — ROADMAP 4.1: prove the cross-identity IPC gate actually REFUSES.
//
// The gate allows a system-trust peer (the compositor) and requires a broker pair rule for
// app-to-app across identities.  The allow path is exercised by every app on every boot; the DENY
// path had never executed, because nothing in the system performs an app-to-app cross-identity
// connect.  A refusal that has never fired is a claim, not a control.
//
// So: spawned into BankVault (Banking identity), this connects to the dbus socket, which is owned
// by dbus-daemon running under the session identity (Personal).  Banking -> Personal, neither of
// them system trust, no pair rule => the kernel must answer EACCES.
//
// Printed rather than asserted, because the interesting outcomes are all distinguishable:
//   EACCES        the gate refused -- what this test exists to show
//   0 / connected the gate did NOT refuse, which means the rule is not doing its job
//   ENOENT        the socket is absent, so the test proved nothing and must not be read as a pass
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DBUS_SOCK "/run/dbus/system_bus_socket"

int main(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("[4.1] xid-test: socket() failed errno=%d\n", errno);
		fflush(stdout);
		return 1;
	}
	struct sockaddr_un sa;
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, DBUS_SOCK, sizeof sa.sun_path - 1);

	errno = 0;
	int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
	int e = errno;
	if (rc == 0)
		printf("[4.1] xid-test: CONNECTED to %s -- gate did NOT refuse (rule not enforced)\n", DBUS_SOCK);
	else if (e == EACCES)
		printf("[4.1] xid-test: EACCES from %s -- cross-identity gate REFUSED, as intended\n", DBUS_SOCK);
	else if (e == ENOENT || e == ECONNREFUSED)
		printf("[4.1] xid-test: errno=%d (socket absent) -- INCONCLUSIVE, not a pass\n", e);
	else
		printf("[4.1] xid-test: errno=%d -- unexpected\n", e);
	fflush(stdout);
	close(fd);
	return 0;
}
