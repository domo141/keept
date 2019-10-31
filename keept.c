/*
 * $ keept.c $
 *
 * Author: Tomi Ollila -- too ät iki piste fi
 *
 *      Copyright (c) 2019 Tomi Ollila
 *          All rights reserved
 *
 * Created: Fri 09 Oct 2015 14:41:53 EEST too
 * Resurrected: Wed Oct 24 23:04:39 2018 +0300
 * Last modified: Sun 12 May 2019 13:24:53 +0300 too
 */

/* SPDX-License-Identifier: BSD-2-Clause */

/* test hint: strace -ff -o trc ./keept q asock bash --norc --noprofile */

#define execvp(f,a) __xexecvp(f,a) // cheat compiler -- as result seems to work

#include "more-warnings.h"

#include <unistd.h>
#include <bsd/unistd.h>  // closefrom()
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <endian.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <sys/uio.h> // writev()
#include <sys/ioctl.h>
#if defined(__linux__) && __linux__
#include <pty.h>
#include <termio.h>
#include <utmp.h> // login_tty()
#else
#include <termios.h> // trial & error on freebsd
#include <libutil.h>
#endif
#include <poll.h>

#include "crrbuf.h"

#undef execvp
// this seems to get harder every time...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"
void execvp(const char * file, const char ** argv);
#pragma GCC diagnostic pop

// (variable) block begin/end -- explicit liveness...
#define BB {
#define BE }

#define null ((void*)0)

#define isizeof (int)sizeof

#define WriteCS(f, s) write((f), (s), sizeof (s) - 1)

#if ! defined __GNUC__ || __GNUC__ < 4
#define __attribute__(x)
#endif

#ifndef DBG
#define DBG 0
#endif

#if DBG
#warning dbg set

#define dbgf(fmt, ...) fprintf(stderr, fmt "\n", __VA_ARGS__)
#define dbg1(f, v) fprintf(stderr, #v ": %" #f "\n", v)
#define dbgcs(cs) fprintf(stderr, "%s\n", #cs)

#define StraceCS(s) WriteCS(222, "hey strace: " s)

#else

#define dbgf(...) do {} while (0)
#define dbg1(...) do {} while (0)
#define dbgcs(...) do {} while (0)

#define StraceCS(s) do {} while (0)

#endif /* DBG */


#if defined (__linux__) && __linux__
#define HAVE_ABSTRACT_SOCKET_NAMESPACE 1
#else
#define HAVE_ABSTRACT_SOCKET_NAMESPACE 0
#endif

#if HAVE_ABSTRACT_SOCKET_NAMESPACE
#define BOOL_ABSTRACT_SOCKET , bool abstract_socket
#define OPTARG_ABSTRACT_SOCKET , abstract_socket
#define PLUS_ABSTRACT_SOCKET + abstract_socket
#else
#define BOOL_ABSTRACT_SOCKET
#define OPTARG_ABSTRACT_SOCKET
#define PLUS_ABSTRACT_SOCKET
#endif

__attribute__((noreturn))
static void usage(const char * prgname, int more)
{
    fprintf(stderr, "\nUsage: %s FLAGS socket [OPTS] [COMMAND [ARG]...]\n\n"
	    , prgname);
    if (more)
#define nl "\n"
	fprintf(stderr,
		"  flags:" nl
		"     q: redraw mode: 'none'  (default: same as initially" nl
		"     b: redraw mode: 'buffer' \\ given, 'wl' if no initial)" nl
		"     l: redraw mode: 'ctrl-l' (both l and w: ctrl-l if win-" nl
		"     w: redraw mode: 'winch'   \\ dow size does not change)" nl
		"     a: attach only, command (if given) not executed" nl
		"     n: no attach, just execute command" nl
		"     m: must create, command to be executed" nl
		"     r: read only attach" nl
		"     x: resize attach window using escape sequence" nl
		"     t: attach even without local tty (on fd 0)" nl
		"     z: send ctrl-z when attaching" nl
#if HAVE_ABSTRACT_SOCKET_NAMESPACE
		"     @: use socket in abstract namespace" nl
#endif
		"  options:" nl
		"    -s size: circular buffer size of latest output stored" nl
		"    -g {rows}x{cols}: initial window size" nl
		"    -o filename: log output (unreadable until chmod(1)'d)" nl
		nl );
#undef nl
    else
	fprintf(stderr, "Enter '%s help' for more information. \n\n", prgname);
    exit(1);
}

__attribute__ ((format(printf, 1,2), noreturn))
static
void die(const char * format, ...)
{
    int err = errno;
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    if (format[strlen(format) - 1] == ':')
	fprintf(stderr, " %s\r\n", strerror(err));
    else
	fputs("\r\n", stderr);
    exit(1);
}

static void xdup2(int o, int n)
{
    if (dup2(o, n) < 0) die("dup2:");
}

static void xmovefd(int ofd, int nfd)
{
    if (ofd == nfd) return;
    xdup2(ofd, nfd);
    close(ofd);
}

static int set_nonblock(int fd)
{
    int v = fcntl(fd, F_GETFL, 0);
    if (v < 0) return -1;
    return fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

static void sigact(int sig, void (*handler)(int), int flags)
{
    struct sigaction action = { .sa_handler = handler,
				/* NOCLDSTOP needed if ptraced */
				.sa_flags = flags|SA_NOCLDSTOP };
    sigemptyset(&action.sa_mask);
    sigaction(sig, &action, NULL);
}

static __attribute__((always_inline))
//#if defined (__OPTIMIZE__) && __OPTIMIZE__ // alternative to (always_inline)
inline
//#endif
int sun_len(int len)
{
    // based on SUN_LEN() in /usr/include/sys/un.h (where available)
    return (int)(intptr_t)(&((struct sockaddr_un *) 0)->sun_path) + len;
}

static int create_sp_usock(int sockopt)
{
    int s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (s < 0)
	die("socket():");
    if (sockopt != 0)
	(void)setsockopt(s, SOL_SOCKET, sockopt, &sockopt, sizeof sockopt);
    return s;
}

static int populate_uaddr(struct sockaddr_un * uaddr,
			  const char * path BOOL_ABSTRACT_SOCKET)
{
    int pl = strlen(path);
    if (pl PLUS_ABSTRACT_SOCKET > isizeof uaddr->sun_path)
	die("Path '%s' too long (%d octets)", path, pl PLUS_ABSTRACT_SOCKET);
    memcpy(uaddr->sun_path PLUS_ABSTRACT_SOCKET, path, pl);
#if HAVE_ABSTRACT_SOCKET_NAMESPACE
    if (abstract_socket) uaddr->sun_path[0] = '\0';
#endif
    return sun_len(pl PLUS_ABSTRACT_SOCKET);
}

static int bind_usock(const char * path BOOL_ABSTRACT_SOCKET)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int alen = populate_uaddr(&addr, path OPTARG_ABSTRACT_SOCKET);
    int s = create_sp_usock(SO_REUSEADDR);

    if (bind(s, (struct sockaddr *)&addr, alen) < 0) {
	int e = errno;
	close(s);
	return -e;
    }
    if (listen(s, 5) < 0) die("listen():");
    return s;
}

static int connect_usock(const char * path BOOL_ABSTRACT_SOCKET)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int alen = populate_uaddr(&addr, path OPTARG_ABSTRACT_SOCKET);
    int s = create_sp_usock(SO_KEEPALIVE);

    // this check here since this is the first try in this program
    if (s <= 2) die("Unexpected open fd %d (<= 2)", s);

    if (connect(s, (struct sockaddr *)&addr, alen) < 0) {
	int e = errno;
	close(s);
	return -e;
    }
    return s;
}

// Note: unnecessary complexity just to save a few bytes, done more for fun...
//       (that's even fewer opcodes that takes the same space...)
struct {
    union {
	volatile int status; // serve()
	struct {
	    bool _read_only;
	    bool _send_ctrl_z;
	    bool _winsize_client;
	    bool _sigwinch;
	} s; // attached()
    } u1;
    bool tty; // attached()
    char redraw_mode; // both
    uint16_t cols, rows; // both
    uint16_t rbufsiz; // serve()
#if defined (__LP64__) && __LP64__
//  uint32_t pad9; // apparently not needed
#endif
    union {
	struct termios saved_tio; // attached()
	struct {
	    pid_t pid; // serve() (+ wait_attach_a_while)
	    volatile int mpfd; // serve()
	} s;
    } u2;
} G;

#define read_only       u1.s._read_only
#define send_ctrl_z     u1.s._send_ctrl_z
#define winsize_client  u1.s._winsize_client
#define sigwinch        u1.s._sigwinch

// recycling...(for now) // may_have_sig may also be unnecessary
#define may_have_sig send_ctrl_z

//
#define wait_attach_a_while u2.s.pid

// attached() uses this, in one way. serve() uses other signal handlers...
static void sighandler(int sig)
{
    G.may_have_sig = true;
    if (sig == SIGWINCH) G.sigwinch = true;
}

static void get_winsz(void)
{
    struct winsize ws;
    if (ioctl(0, TIOCGWINSZ, &ws) < 0) {
	//warn("getting window size failed");
	G.cols = G.rows = 0;
    }
    else {
	G.cols = ws.ws_col;
	G.rows = ws.ws_row; // we'll see if these needed //
    }
}

static void reset_tio(void)
{
    tcsetattr(0, TCSAFLUSH, &G.u2.saved_tio);
}

static void detach(int n) __attribute__((noreturn));
static void detach(int n)
{
    if (n == 0) WriteCS(2, "\r\n[detached]\r\n");
    else fprintf(stderr, "\r\n[detached (signal %d)]\r\n", n);
    exit(n);
}

enum {
    // could be anything, that is same in big and little endian encoding
    BYTES = (int32_t)0xb7aaaab7,
    CINIT = 0x1b17171b,
    RDMODE = (int32_t)0x3d50503d,
    WINSIZ = (int32_t)0xa5c8c8a5,
    CEXIT = (int32_t)0xe81717e8
};

// global data buffer used almost everywhere (and a bit risky...)
unsigned char buf[4096];

static void exitmsg_to_fd(int fd, bool normal_exit, uint8_t status)
{
    const char * s = normal_exit? "keept: exit": "terminated by signal";
    int l = snprintf((char *)buf, sizeof buf,
		     // XXX fd value depencency/cohesion...
		     fd == 2? "\n[%s %u]\n": "\r\n[%s %u]\r\n", s, status);
    write(fd, buf, l);
}

static int attached(int s)
{
    if (G.tty) {
	if (G.cols == 0) get_winsz();
	struct termios tio = G.u2.saved_tio;
	// see ttydefaults.h and then compare w/ what other sw does here
	cfmakeraw(&tio);
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	atexit(reset_tio);
	tcsetattr(0, TCSANOW, &tio);
	sigact(SIGWINCH, sighandler, 0);
    }
    sigact(SIGHUP, detach, 0);
    sigact(SIGINT, detach, 0);
    sigact(SIGTERM, detach, 0);

    (*(uint32_t *)buf) = (uint32_t)CINIT;
    buf[4] = G.cols >> 8; buf[5] = G.cols & 0xff;
    buf[6] = G.rows >> 8; buf[7] = G.rows & 0xff;
    if (G.redraw_mode & 128) {
	buf[8] = 1; // immediate first connection //
	G.redraw_mode &= 127;
    } else
	buf[8] = G.redraw_mode;
    buf[9] = G.read_only;
    buf[10] = G.winsize_client;
    buf[11] = G.send_ctrl_z;
    write(s, buf, 12);

    struct pollfd pfds[2] = {
	[0] = { .fd = 0, .events = POLLIN },
	[1] = { .fd = s, .events = POLLIN }
    };

    while (1) {
	int n = poll(pfds, 2, -1);
	(void)n;
	if (pfds[0].revents) {
	    int l = read(0, buf + 4, sizeof buf - 4);
	    if (l <= 0) {
		if (l < 0) die("STDIN read failure:");
		else die("STDIN EOF!");
	    }
	    if (l == 1) {
		if (buf[4] == '\032') /* ctrl-z */ detach(0);

		if (buf[4] == '\014' && ! G.read_only && G.redraw_mode >= 4) {
		    // ctrl-l pressed and redraw mode & ( l | w ) and ...
		    // note: serve() sends signal to child if size changes
		    *((uint32_t *)buf + 3) = (uint32_t)WINSIZ;
		    buf[16] = G.cols >> 8; buf[17] = G.cols & 0xff;
		    buf[18] = G.rows >> 8; buf[19] = G.rows & 0xff;
		    write/*fully*/(s, buf + 12, 8);
		}
	    }
	    if (! G.read_only) {
		(*(uint32_t *)buf) = (uint32_t)BYTES;
		write/*fully*/(s, buf, l + 4);
	    }
	}
	if (pfds[1].revents) {
	    int len;
	    len = read(s, buf, sizeof buf);
	    if (len > 0) {
		if (len < 5) continue;

		if ((*(uint32_t*)buf) == (uint32_t)BYTES) {
		    write/*fully*/(1, buf + 4, len - 4);
		    continue;
		}
		if ((*(uint32_t*)buf) == (uint32_t)RDMODE) {
		    G.redraw_mode = buf[4] & 15;
		    continue;
		}
		if ((*(uint32_t*)buf) == (uint32_t)CEXIT) {
		    // len check tba (highly unlikely != 6)
		    int rv = buf[5];
		    exitmsg_to_fd(1, buf[4], buf[5]);
		    return rv;
		}
		if ((*(uint32_t*)buf) == (uint32_t)WINSIZ) {
		    if (len < 8) continue;
		    int cols = (buf[4] << 8) + buf[5];
		    int rows = (buf[6] << 8) + buf[7];
		    // window size change escape sequence //
		    len = snprintf((char *)buf, isizeof buf,
				   "\033[8;%d;%dt", rows, cols);
		    if (len < isizeof buf) write(1, buf, len);
		    continue;
		}
		fprintf(stderr,
			"Unknown command code %02x%02x\r\n", buf[0], buf[1]);
		continue;
	    }
	    if (len == 0)
		die("\r\nUnexpected EOF from keept daemon");
	    else
		die("\r\nReading from keept daemon failed:");
	}
	if (G.may_have_sig) {
	    G.may_have_sig = false;
	    if (G.sigwinch) {
		G.sigwinch = false;
		get_winsz();
		(*(uint32_t *)buf) = (uint32_t)WINSIZ;
		buf[4] = G.cols >> 8; buf[5] = G.cols & 0xff;
		buf[6] = G.rows >> 8; buf[7] = G.rows & 0xff;
		write(s, buf, 8);
	    }
	}
    }
    return 0;
}

static bool winsize_to_tty(const unsigned char * colsrows)
{
    struct winsize ws = {
	.ws_col = (colsrows[0] << 8) + colsrows[1],
	.ws_row = (colsrows[2] << 8) + colsrows[3]
    };
    if (ws.ws_col == 0 || ws.ws_row == 0) return false;
    // no point send WINSIZ is size does not change -- child not signaled //
    if (ws.ws_col == G.cols && ws.ws_row == G.rows) return false;

#if 0 // test print: need -o file cmd line option...
#warning if 0 here
    fprintf(stderr, "%s: %d <- %d x %d <- %d\n", __func__,
	    ws.ws_col, G.cols, ws.ws_row, G.rows);
#endif

    if (ioctl(1, TIOCSWINSZ, &ws) == 0) {
	G.cols = ws.ws_col;
	G.rows = ws.ws_row;
	return true;
    }
    return false;
}

static void log_date(int fd, const char * w)
{
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    int l = snprintf((char*)buf, sizeof buf, "Log %s on ", w);
    l += strftime((char*)buf + l, sizeof buf - l,
		  "%Y-%m-%d %H:%M:%S %z\n", &tm);
    write(fd, buf, l);
}

// serve() fd's
// 0: server socket
// 1: pty
// 2: output file (or server socket)
// other: client fd:s -- and after eof pipe
//

static void sigalrmhandler(int sig)
{
    (void)sig;
    close(1); // pty fd
}

// man 2 setsid says:
//   If a process that is a session leader terminates, then a SIGHUP  signal
//   is sent to each process in the foreground process group of the control‐
//   ling terminal.
// So, usually any child processes hanging on that tty exits, and pty on our
// side will get EOF (or EIO error). Just that this process may not have read
// all of that pty data and therefore 5 sec alarm timeout is sent.
// After that 5 secs, sigalrmhandler() above will close ptyfd so we definitely
// get out of the first while (1) loop in serve() (child may continue running
// but this program doesn't care that anymore...).
// Alternativey, child can close its stdin, stdout and stderr -- and handle
// forthcoming SIGHUP. In this case the second while (1) loop will wait
// the SIGCHLD. New connections may request ring buffer data before those
// are informed of the EOF situation.

static void sigchldhandler(int sig)
{
    (void)sig;
    int status;
    if (waitpid(G.u2.s.pid, &status, WNOHANG) == G.u2.s.pid) {
	G.u1.status = status;
	if (G.u2.s.mpfd > 0) write(G.u2.s.mpfd, "", 1);
	else alarm(5);
    }
}

static pid_t serve(int ss, int o, const char ** argv)
{
    pid_t pid = fork(); // we'll need one fork() more for parent to wait...
    if (pid > 0) return pid;
    if (pid < 0) die("fork failed:");

    StraceCS("intermediate child");

    // second fork, for parent of this to wait, and grandchild to execute...
    pid = fork();
    if (pid > 0) _exit(0);
    if (pid < 0) die("fork failed:");

    StraceCS("grandchild serve() process");
    xmovefd(ss, 0);

    // better chance first connect doesn't lose any terminal output
    if (G.wait_attach_a_while) {
	struct pollfd pfd = { .fd = 0, .events = POLLIN };
	// 2 seconds for now
	(void)poll(&pfd, 1, 2000); // failure unlikely
    }

    CrRBuf * crrbuf;
    if (G.rbufsiz) {
	crrbuf = crrbuf_create(G.rbufsiz);
	if (crrbuf == null) die("Out of Memory!");
    }
    else crrbuf = null;

    char pidstr[32]; snprintf(pidstr, sizeof pidstr, "%d", getpid());
    setenv("KEEPT_PID", pidstr, 1);

    BB;
    int tty, pty;
    struct winsize ws;
    if (G.cols > 0) {
	ws.ws_col = G.cols;
	ws.ws_row = G.rows;
    }
    else {
	if (ioctl(1, TIOCGWINSZ, &ws) < 0) {
	    ws.ws_col = 80;
	    ws.ws_row = 24;
	}
	G.cols = ws.ws_col;
	G.rows = ws.ws_row;
    }
    if (openpty(&pty, &tty, null, null, &ws) < 0)
	die("openpty failed:");

    /* complete daemonize */
    xmovefd(pty, 1); xdup2(o, 2); setsid();
    if (o != 0) close(o);
    /* fd 2 is now either server socket or log file -- having log file at
       fd 2 helps dev testing as any function can write there (stderr!)
       (tester just needs to give outfile (-o) option) */

    pid = fork();
    if (pid < 0) exit(88); // XXX could we write error msg to socket ?
    if (pid == 0) {
	/* child */
	StraceCS("serve() child");
	login_tty(tty);
	execvp(argv[0], argv);
	die("execve failed:");
    }
    /* parent */
    close(tty);
    set_nonblock(1); // pty
    G.u2.s.pid = pid;
    G.u2.s.mpfd = 0;
    BE;

    G.u1.status = -1;

    sigact(SIGCHLD, sigchldhandler, 0);
    sigact(SIGALRM, sigalrmhandler, 0);
    sigact(SIGPIPE, SIG_IGN, 0);

    if (G.redraw_mode == 0) G.redraw_mode = 12; // 'wl'

#define MAXCONNS 128 // actually, 126 for connections...
    struct pollfd pfds[MAXCONNS] = {
	[0] = { .fd = 0 }, // server socket
	[1] = { .fd = 1 } // pty
    };
    unsigned char flags[MAXCONNS] = { 0 };
    int maxi = 2;

    for (int i = 0; i < MAXCONNS; i++) pfds[i].events = POLLIN;

    while (1) {
	int n = poll(pfds, maxi, -1);
	(void)n;
	if (pfds[1].revents) {
	    int l = read(1, buf + 4, sizeof buf - 4);
	    if (l <= 0) {
		if (l < 0 && errno == EINTR) continue; // improbable...
		// EOF (in any form) go to second loop waiting for exit...
		break;
	    }
	    if (o != 0) write/*fully*/(2, buf + 4, l);
	    if (crrbuf) crrbuf_append(crrbuf, buf + 4, l);
	    (*(uint32_t *)buf) = (uint32_t)BYTES;
	    for (int i = 2; i < maxi; i++) write(pfds[i].fd, buf, l + 4);
	    // if (n == 1) continue; // could be used everywhere...
	}
	if (pfds[0].revents) {
	    int s = accept(0, null, null);
	    if (s >= 0) {
		if (maxi == MAXCONNS) {
		    // XXX send protocol msg telling table full
		    close(s);
		}
		else {
		    set_nonblock(s);
		    pfds[maxi].fd = s;
		    // check if that fd already has some data //
		    poll(pfds + maxi++, 1, 0); // if so will be available below
		}
	    }
	}
	for (int i = 2; i < maxi; i++) {
	    if (pfds[i].revents) {
		int len = read(pfds[i].fd, buf, sizeof buf);
		if (len > 0) {
		    if (flags[i] & 1) continue; // read-only
		    if (len < 5) continue;

		    if ((*(uint32_t*)buf) == (uint32_t)BYTES) {
			write/*fully*/(1, buf + 4, len - 4);
			//poll(0,0,200); // 200ms wait, test code
			continue;
		    }
		    if ((*(uint32_t*)buf) == (uint32_t)WINSIZ) {
			// window size change (perhaps) //
			if (len == 8) winsize_to_tty(&buf[4]);
			continue;
		    }
		    if ((*(uint32_t*)buf) == (uint32_t)CINIT) {
			// initial request //
			if (len != 12) goto drop_conn1;
			if (buf[11]) write(1, "\032", 1); // ctrl-z
			if (buf[8] == 0) { // no redraw mode option given
			    buf[8] = G.redraw_mode;
			    unsigned char resp[8];
			    (*(uint32_t *)resp) = (uint32_t)RDMODE;
			    resp[4] = G.redraw_mode;
			    write(pfds[i].fd, resp, 5);
			}
			if (buf[10]) { // winsize_to_kilent
			    buf[8] &= ~8;
			    unsigned char resp[8];
			    (*(uint32_t *)resp) = (uint32_t)WINSIZ;
			    resp[4] = G.cols >> 8; resp[5] = G.cols & 0xff;
			    resp[6] = G.rows >> 8; resp[7] = G.rows & 0xff;
			    write(pfds[i].fd, resp, 8);
			}
			if (buf[8] & 2) { // redraw mode 'buffer'
			    if (crrbuf) {
				struct iovec iov[3];
				int iolen = crrbuf_data(crrbuf, &iov[1]);
				unsigned char lb[4];
				int count = iov[1].iov_len;
				if (iolen == 2) count += iov[2].iov_len;
				count += 4;
				(*(uint32_t *)lb) = (uint32_t)BYTES;
				iov[0].iov_base = lb; iov[0].iov_len = 4;
				int rv = writev(pfds[i].fd, iov, iolen + 1);
				// in initial message write checked...
				if (rv != count) goto drop_conn1;
			    }
			}
			if (buf[8] & 8) { // redraw mode 'winch'
			    if (buf[8] & 4) { // but if also 'ctl-l'...
				bool resized = winsize_to_tty(&buf[4]);
				if (! resized) write(1, "\f", 1); // ctrl-l
			    }
			    else winsize_to_tty(&buf[4]);
			}
			else if (buf[8] & 4) write(1, "\f", 1); // ctrl-l
			// ...and no redraw if buf[8] == 1

			if (buf[9]) flags[i] |= 1; // read-only
			continue;
		    }
		}
		// fall to drop_conn1 (unknown request) if no match above
	    drop_conn1:
		close(pfds[i].fd);
		maxi--;
		if (i == maxi) continue;
		pfds[i] = pfds[maxi];
		flags[i] = flags[maxi];
		i--;
	    }
	}
    }
#   define drop_conn1 fix_goto_target_label_in_code_below

    // Here when reading from pty returned 0 or -1.
    // We may have already received SIGCHLD (if waitpid() succeeded,
    // G.u1.status >= 0). If not, SIGCHLD (and G.u1.status change) may
    // happen at any moment below.

    if (G.u1.status >= 0) { alarm(0); goto _exit; }

    BB;
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe(2) failed:"); // improbable!
    dup2(pipefd[0], 1);
    G.u2.s.mpfd = pipefd[1];
    BE;
    alarm(0);

    if (G.u1.status >= 0) goto _exit;

    while (1) {
	int n = poll(pfds, maxi, -1);
	(void)n;
	if (pfds[1].revents) {
	    // here if signal handler wrote byte to (pipe) fd 1
	    (void)read(1, buf, sizeof buf);
	    if (G.u1.status >= 0) goto _exit;
	}
	if (pfds[0].revents) {
	    int s = accept(0, null, null);
	    if (s >= 0) {
		if (maxi == MAXCONNS) {
		    // XXX send protocol msg telling table full
		    close(s);
		}
		else {
		    set_nonblock(s);
		    pfds[maxi].fd = s;
		    // check if that fd already has some data //
		    poll(pfds + maxi++, 1, 0); // if so will be available below
		}
	    }
	}
	for (int i = 2; i < maxi; i++) {
	    if (pfds[i].revents) {
		int len = read(pfds[i].fd, buf, sizeof buf);
		if (len > 0) {
		    if (flags[i] & 1) continue; // read-only
		    if (len < 5) continue;

		    if ((*(uint32_t*)buf) == (uint32_t)BYTES) {
			// waiting for child exit, no reader there //
			continue;
		    }
		    if ((*(uint32_t*)buf) == (uint32_t)WINSIZ) {
			// ditto //
			continue;
		    }
		    if ((*(uint32_t*)buf) == (uint32_t)CINIT) {
			// initial request //
			if (len != 12) goto drop_conn2;
			if (buf[8] == 0) { // no redraw mode option given
			    buf[8] = G.redraw_mode;
			    // here we don't care inform client anymore
			}
			if (buf[8] & 2) { // redraw mode 'buffer'
			    if (crrbuf) {
				struct iovec iov[3];
				int iolen = crrbuf_data(crrbuf, &iov[1]);
				unsigned char lb[4];
				int count = iov[1].iov_len;
				if (iolen == 2) count += iov[2].iov_len;
				count += 4;
				(*(uint32_t *)lb) = (uint32_t)BYTES;
				iov[0].iov_base = lb; iov[0].iov_len = 4;
				int rv = writev(pfds[i].fd, iov, iolen + 1);
				// in initial message write checked...
				if (rv != count) goto drop_conn2;
			    }
			}
			WriteCS(pfds[i].fd, "\r\n[EOF]\r\n");
			continue;
		    }
		}
		// fall to drop_conn2 (unknown request) if no match above
	    drop_conn2:
		close(pfds[i].fd);
		maxi--;
		if (i == maxi) continue;
		pfds[i] = pfds[maxi];
		flags[i] = flags[maxi];
		i--;
	    }
	}
    }
_exit:
    ; // or {} // to make compiler not fail here...
    int status = G.u1.status;
    bool normal_exit = WIFEXITED(status);
    status = normal_exit? WEXITSTATUS(status): WTERMSIG(status);

    if (o != 0) {
	exitmsg_to_fd(2, normal_exit, status & 0xff);
	log_date(2, "done");
    }
    (*(uint32_t *)buf) = (uint32_t)CEXIT;
    buf[4] = normal_exit;
    buf[5] = status & 0xff;
    for (int i = 2; i < maxi; i++) write(pfds[i].fd, buf, 6);
    exit(0);
}


int main(int argc, const char * argv[])
{
    if (argc < 3) usage(argv[0], argc - 1); // 0 or 1, 1 for more information

    bool notty_ok = false;
    bool attach_only = false;
    bool no_attach = false;
    bool must_create = false;
#if HAVE_ABSTRACT_SOCKET_NAMESPACE
    bool abstract_socket = false;
#endif
    for (int c, i = 0; (c = argv[1][i]); i++) {
	dbg1(c, c);
	switch (c) {
	case '-': break; // ignored
	case 'a': attach_only = true; break;
	case 'n': no_attach = true;   break;
	case 'm': must_create = true; break;
	case 'r': G.read_only = true; break;
	case 'q': G.redraw_mode = 1;  break; // none   \.
	case 'b': G.redraw_mode |= 2; break; // buffer  \.
	case 'l': G.redraw_mode |= 4; break; // ctrl-l   |- rest logic in serve
	case 'w': G.redraw_mode |= 8; break; // winch   /'
	case 't': notty_ok = true;    break;
	case 'x': G.winsize_client = true; break;
	case 'z': G.send_ctrl_z = true; break;
#if HAVE_ABSTRACT_SOCKET_NAMESPACE
	case '@': abstract_socket = true; break;
#endif
	default:
	    die("'%c': unknown flag", c);
	}
    }
    dbg1(d, G.redraw_mode);
    dbg1(d, attach_only);
    dbg1(d, no_attach);
    dbg1(d, G.send_ctrl_z);
    dbg1(d, G.winsize_client);

    if (no_attach) {
	if (attach_only) die("Cannot do both 'a' and 'n'");
	must_create = true;
    }
    if (attach_only && must_create) die("Cannot do both 'a' and 'm'");

    if (! must_create) {
	const char * keept_pid = getenv("KEEPT_PID");
	if (keept_pid != null) { // should we allow 'n' and 'm' ?
#define nl "\n"
	    fprintf(
		stderr, nl
		" You are already attached to keept process %s." nl nl
		" As a precaution, running keept(1) from attached process" nl
		" is disabled, as it often would lead to unmanageable live" nl
		" loop. You can run keept(1) here if you unset KEEPT_PID" nl
		" environment variable. Note that KEEPT_PID may get" nl
		" undefined by some reasons so this protection is not fool" nl
		" proof." nl, keept_pid);
#undef nl
	    exit(1);
	}
    }
    const char * sockname = argv[2];
    if (sockname[0] == '\0') die("Zero-length socket name!");

    //die("as: %d, sockname: %s", abstract_socket, sockname); // test code

    const char * outfile = null;
    const char * rbufsiz = null;
    const char * geosize = null;

    argv += 3;
    argc -= 3;

    while (*argv) {
	if (*argv[0] != '-') break;
	const char * arg = *argv++; argc--;
	if (arg[1] == '-' && arg[2] == '\0') break; // '--'
	const char ** avref;
	switch (arg[1]) {
	case 'o': avref = &outfile; goto getargval;
	case 's': avref = &rbufsiz; goto getargval;
	case 'g': avref = &geosize; goto getargval;
	default:
	    die("'-%c': unknown option", arg[1]);
	}
	continue;
    getargval:
	if (arg[2] != '\0') {
	    *avref = arg + 2;
	    continue;
	}
	if (*argv == null)
	    die("No value for option '%s'", arg);
	*avref = *argv++; argc--;
    }

    if (rbufsiz) {
	errno = 0;
	char * ep;
	long l = strtol(rbufsiz, &ep, 10);
	if (errno) die("-s %s: invalid value", rbufsiz);
	if (l < 0) die ("-s %s: value too small", rbufsiz);
	if (l > 16384) die ("-s %s: value too large", rbufsiz);
	G.rbufsiz = l;
    }
    else G.rbufsiz = (G.redraw_mode & 2)? 1024: 0;
    dbg1(d, G.rbufsiz);

    if (geosize) {
	errno = 0;
	char * ep;
	long l = strtol(geosize, &ep, 10);
	if (errno) die("-g %s: invalid value", geosize);
	if (l <= 0) die ("-g %s: cols value too small", geosize);
	// XXX is even 1000 too much ?
	if (l > 1000) die ("-g %s: cols value too large", geosize);
	if (*ep != 'x') die ("-g %s: cols x rows delimiter not 'x'", geosize);
	G.cols = l;
	l = strtol(ep + 1, &ep, 10);
	if (errno) die("-g %s: invalid value (rows)", geosize);
	if (l <= 0) die ("-g %s: rows value too small", geosize);
	// XXX ditto
	if (l > 1000) die ("-g %s: rows value too large", geosize);
	if (*ep != '\0') die ("-g %s: trailing characters", geosize);
	G.rows = l;
    }
    if (argc == 0 && must_create) die("Command (and args) missing");

    dbgf("-- argc: %d outfile: %s\n", argc, outfile);

    struct stat statbuf; statbuf.st_mode = 0;

#if HAVE_ABSTRACT_SOCKET_NAMESPACE
    if (! abstract_socket)
#endif
	(void)stat(sockname, &statbuf);

    bool socketfile_exists = false;
    if (statbuf.st_mode != 0) {
	if (! S_ISSOCK(statbuf.st_mode))
	    die("File '%s' exists and is not a socket", sockname);
	else
	    socketfile_exists = true;
    }

    if (! no_attach) {
	// could open /dev/tty on demand, but probably would not bring any bene
	if (tcgetattr(0, &G.u2.saved_tio) < 0) {
	    if (! notty_ok)
		die("Fd 0 not on a tty... Use 'n' or 't' to continue anyway.");
	}
	else G.tty = true;
    }

    closefrom(3);

    int s = connect_usock(sockname OPTARG_ABSTRACT_SOCKET);
    if (s >= 0) {
	if (must_create)
	    die("Connected to live socket when command is to be executed");
	return attached(s);
    }
    if (s != -ECONNREFUSED && s != -ENOENT) {
	errno = -s; // hmm, not happy but...
	die("Connecting to socket failed:");
    }
    if (attach_only)
	die("No live socket to attach to");

    if (argc == 0)
	die("Command (and args) missing");

    if (socketfile_exists) unlink(sockname);

    s = bind_usock(sockname OPTARG_ABSTRACT_SOCKET);
    if (s < 0) {
	errno = -s;
	die("Binding socket failed:");
    }
    int o;
    if (outfile) {
	// outfile is not be readable by default; user when chmod(1)ing outfile
	// acknowledges that e.g. cat(1)ing it in keept(1)ed env will
	// cause liveloop while outfile filling up...
	// so, user can do chmod +r outfile && less outfile
	(void)unlink(outfile); // if this fails, outfile perms preserved...
	o = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0000);
	if (o < 0) die("Writing to '%s' failed:", outfile);
	tzset();
	log_date(o, "started");
    }
    else o = 0; // we always have fd 0 in other use (this helps serve() xdup2)

    G.wait_attach_a_while = ! no_attach;
    BB;
    setenv("KEEPT_SOCKARG", sockname, 1);
    pid_t pid = serve(s, o, argv);
    int status;
    errno = 0; // waitpid could, in theory, succeed but not return pid...
    while (waitpid(pid, &status, 0) != pid) {
	if (errno != EINTR) {
	    if (status == 0) status = 14; // ALRM :O
	    break;
	}
	errno = 0; // ... in which case errno could stay EINTR forever...
    }
    if (status != 0) exit(status);
    BE;

    if (no_attach) return 0;

    if (o) close(o);
    close(s);

    s = connect_usock(sockname OPTARG_ABSTRACT_SOCKET);
    if (s < 0) {
	errno = -s; // hmm, not happy but...
	die("Connecting to socket failed:");
    }
    G.redraw_mode = G.redraw_mode | 128; // bit 7 for immediate first connection
    return attached(s);
}

/*
 * Local variables:
 * mode: c
 * c-file-style: "stroustrup"
 * tab-width: 8
 * End:
 */
