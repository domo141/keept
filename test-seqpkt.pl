#!/usr/bin/perl
# -*- mode: cperl; cperl-indent-level: 4 -*-
# $ test-seqpkt.pl $
#
# Author: Tomi Ollila -- too ät iki piste fi
#
#	Copyright (c) 2018 Tomi Ollila
#	    All rights reserved
#
# Created: Thu 22 Nov 2018 20:04:18 EET too
# Last modified: Sat 19 Jan 2019 19:24:20 +0200 too

# SPDX-License-Identifier: BSD-2-Clause

# observe that seqpacket sockets preserve message boundaries
# and, by using small bufsize, data drop on seqpacket sockets

use 5.8.1;
use strict;
use warnings;
use Socket;

$ENV{'PATH'} = '/sbin:/usr/sbin:/bin:/usr/bin';

die "
Usage: $0 '(s|p)' [bufsize]\n
  s: SOCK_STREAM -- p: SOCK_SEQPACKET socket\n
  bufsize: read buffer size if given\n\n" unless @ARGV;

my $type;
   if ($ARGV[0] eq 's') { $type = SOCK_STREAM }
elsif ($ARGV[0] eq 'p') { $type = SOCK_SEQPACKET }
else { die "'$ARGV[0]' not 's' nor 'p'\n" }

my $bufsize = ($ARGV[1] || 0) + 0;
$bufsize = 512 unless $bufsize > 0;

socketpair S1, S2, AF_UNIX, $type, 0;

syswrite S1, "<message 1>";
syswrite S1, "<message 2>";
syswrite S1, "<message 3>";
syswrite S1, "EOF";

while (1) {
    sysread S2, $_, $bufsize or die $!;
    print $_, "\n";
    last if /EOF/;
}
