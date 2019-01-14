/*
 * $ crrbuf.h $
 *
 * Author: Tomi Ollila -- too ät iki piste fi
 *
 *      Copyright (c) 2018 Tomi Ollila
 *          All rights reserved
 *
 * Created: Tue 11 Nov 2008 21:04:29 EET too
 * Last modified: Tue 20 Nov 2018 19:11:17 +0200 too
 */

/* SPDX-License-Identifier: BSD-2-Clause */

#include "more-warnings.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "crrbuf.h"

//#define DEBUG_RB 1
#define DEBUG_RB 0

#if DEBUG_RB
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
static void dbprintf(const char * format, ...)
{
	char buf[1024]; unsigned int l; va_list ap;
	//int fd = open("rb_debug", O_WRONLY|O_CREAT|O_APPEND, 0644);
	//if (fd < 0) abort();
	va_start(ap, format);
	l = vsnprintf(buf, sizeof buf, format, ap);
	va_end(ap);
	write(1, buf, l > sizeof buf? sizeof buf: l);
	//write(fd, buf, l > sizeof buf? sizeof buf: l);
	//close(fd);
}
#define d1(x) dbprintf x
#define d0(x) do {} while (0)
#else
#define d1(x) do {} while (0)
#define d0(x) do {} while (0)
#endif // DEBUG_RB

#define null ((void *)0)

struct _CrRBuf {
	uint32_t max; /* +1 */
	uint32_t next;
	uint32_t lastnl; /* +1 */
	uint16_t bufsize;
	char sizecrossed; // no longer used, works as pad
	unsigned char prevchar;
	unsigned char buf[];
};

/* initial implementation -- byte at a time */

/* fails only on out-of-mem */
CrRBuf * crrbuf_create(int bufsize)
{
	/**/ if (bufsize < 16) bufsize = 16;
	else if (bufsize > 16384) bufsize = 16384;
/* bufsize have to be power of 2 (otherwise problem when integer wraps) */
	else if ((bufsize & (bufsize - 1)) != 0) {
		bufsize = 1 << (32 - __builtin_clz((unsigned int)bufsize));
	}
	CrRBuf * rb = malloc(sizeof *rb + bufsize);
	if (rb == null)
		return null;
	d1(("* bufsize: %d\n", bufsize));
	memset(rb, 0, sizeof *rb);
	rb->bufsize = (uint16_t)bufsize;
	crrbuf_append(rb, (const unsigned char *)"\r\n", 2);
	return rb;
}

/*
 * crrbuf_append() adds given text data to the buffer, handling CRLF, LFCR
 * and finally plain CR specially. This way output that writes to one line
 * continuously (using CR to move cursor back at the beginning of line)
 * does not use all buffer space. This provides somewhat good experience
 * without more knowledge of control chars and escape sequences
 * (and, especially, without copying data around).
 * In addition to that the following 'characters' are not buffered:
 *   0x07: (audible?) bell -- minimum effort noise cancellation
 */
void crrbuf_append(CrRBuf * rb, const unsigned char * s, int len)
{
	while (len-- > 0) {
		unsigned char c = *s++;
		switch (c) {
		case '\n':
			d0(("xx %d ", rb->next));
			if ((int32_t)(rb->max - rb->next) > 0)
				rb->next = rb->max;
			d0(("// %d ", rb->next));

			if (rb->prevchar == '\r') {
				rb->buf[rb->next++ % rb->bufsize] = '\r';
				c = 0;
			}
			rb->buf[rb->next++ % rb->bufsize] = '\n';
			rb->lastnl = rb->next;
			break;
		case '\r':
			if (rb->prevchar == '\n') {
				rb->buf[rb->next++ % rb->bufsize] = '\r';
				c = 0;
			}
			else {
				if ((int32_t)(rb->next - rb->max) > 0)
					rb->max = rb->next;
				rb->next = rb->lastnl;
			}
			break;
		// not logging:
		case 0x07: // bell
			break;
#if 0
		/* trying BS handling broke e.g. ^H ESC [ K sequence badly.
		 * w/ some effort handling that stream of octets at rb->max
		 * could be handled, but it is SMOP, and probably not last */
		case 0x08: /* backspace */
			if ((int32_t)(rb->next - rb->lastnl) > 0)
				// should we also do some rb->max handling?
				rb->next--;
			break;
#endif
		default:
			d0(("%d ", rb->next));
			rb->buf[rb->next++ % rb->bufsize] = c;
		}
		rb->prevchar = c;
	}
	if ((int32_t)(rb->next - rb->max) > 0)
		rb->max = rb->next;

	// it is highly unlikely that when rb->max wraps at 4GiB
	// the data is requested, more likely sizecrossed is set
	// but backward movements moves rb->next back...
	// (actually, this comment may be invalid...)
//	if (rb->sizecrossed == 0 && rb->max > rb->bufsize)
//		rb->sizecrossed = 1;
}

int crrbuf_data(CrRBuf * rb, struct iovec iov[2])
{
	uint32_t umax;
	// if last input char was \r, add it to output. a hack
	// common use case (with progress bars) is to move cursor
	// at the beginning of line after data written...
	d0(("max %d next %d lastnl %d\n", rb->max, rb->next, rb->lastnl));
	if ((int32_t)(rb->max - rb->next) > 0 && rb->next == rb->lastnl) {
		umax = rb->max + 1;
		rb->buf[rb->max % rb->bufsize] = '\r';
	}
	else
		umax = rb->max;

	uint16_t mix = umax % rb->bufsize;

#if DEBUG_RB && 0
	uint16_t bs = rb->bufsize;

	d1(("\r\n umax %d (%d) <- mix"
	    "\r\n next %d (%d) "
	    "\r\n lastnl %d (%d)"
	    "\r\n last chars: %d %d %d %d %d %d %d %d"
	    "\r\n", umax, umax % bs,
	    rb->next, rb->next % bs, /**/ rb->lastnl, rb->lastnl % bs,
	    rb->buf[(umax - 8) % bs], rb->buf[(umax - 7) % bs],
	    rb->buf[(umax - 6) % bs], rb->buf[(umax - 5) % bs],
	    rb->buf[(umax - 4) % bs], rb->buf[(umax - 3) % bs],
	    rb->buf[(umax - 2) % bs], rb->buf[(umax - 1) % bs]));
#endif /* DEBUG_RB */

	//if (rb->sizecrossed && mix != 0) {
	if (umax > rb->bufsize && mix != 0) {
		iov[0].iov_base = rb->buf + mix;
		iov[0].iov_len  = rb->bufsize - mix;
		iov[1].iov_base = rb->buf;
		iov[1].iov_len  = mix;
		return 2;
	}
	else {
		iov[0].iov_base = rb->buf;
		iov[0].iov_len  = mix ? mix: rb->bufsize;
		return 1;
	}
}


#if defined(TEST) && TEST
#include <unistd.h>
#define WriteCS(f, s) write(f, s, sizeof s - 1)
int main(int argc, char * argv[])
{
	int rbsiz = 64;
	if (argc > 1)
		rbsiz = atoi(argv[1]);
	CrRBuf * rb = crrbuf_create(rbsiz);
	unsigned char buf[24];
	while (1) {
		int len = read(0, buf, sizeof buf);
		if (len <= 0) exit(-len);
		WriteCS(1, "input: "); write(1, buf, len);
#if 1
		for (int i = 0; i < len; i++) {
			// manual test haxes...
			switch (buf[i]) {
			case ',': buf[i] = '\r'; break;
			// in next two, usecase is to change last character
			case '.': buf[i+1] = '/'; break; // for \n avoidance
			case '-': buf[i+1] = '\r'; break; // trailing \r
			}
		}
#endif
		crrbuf_append(rb, buf, len);
		WriteCS(1, "================\n");
		struct iovec iov[2];
		int iovcnt = crrbuf_data(rb, iov);
		writev(1, iov, iovcnt);
		WriteCS(1, ",,\n");
		//WriteCS(1, ",,,,,,,,,,,,,,,,\n");
	}
	return 10; // not reached //
}
#endif

/*
 * Local variables:
 * mode: c
 * c-file-style: "linux"
 * tab-width: 8
 * End:
 */
