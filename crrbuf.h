/*
 * $ crrbuf.h $
 *
 * Author: Tomi Ollila -- too ät iki piste fi
 *
 *      Copyright (c) 2018 Tomi Ollila
 *          All rights reserved
 *
 * Created: Wed 11 Nov 2008 21:04:53 EET too
 * Last modified: Fri 26 Oct 2018 12:28:55 +0300 too
 */

/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef CRRBUF_H
#define CRRBUF_H

typedef struct _CrRBuf CrRBuf;

CrRBuf * crrbuf_create(int bufsize);
void crrbuf_append(CrRBuf * rb, const unsigned char * s, int len);
int crrbuf_data(CrRBuf * rb, struct iovec iov[2]);

#define crrbuf_delete(rb) free((rb))

#endif /* CRRBUF_H */
