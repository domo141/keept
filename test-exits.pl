#!/usr/bin/perl
# -*- mode: cperl; cperl-indent-level: 4 -*-
# $ test-exits.pl $
#
# Author: Tomi Ollila -- too ät iki piste fi
#
#	Copyright (c) 2018 Tomi Ollila
#	    All rights reserved
#
# Created: Fri 23 Nov 2018 21:56:52 EET too
# Last modified: Sat 19 Jan 2019 19:21:53 +0200 too

# SPDX-License-Identifier: BSD-2-Clause

# cli runs: ./test-exits.pl cwe | { cat; echo EOF; }; echo EXIT
#           ./test-exits.pl ewc; echo EXIT; sleep 2

# keept runs: strace -ttff -otl ./keept qm asock ./test-exits.pl ewc
#             strace -ttff -otl ./keept qm asock ./test-exits.pl cwe

use 5.8.1;
use strict;
use warnings;

use POSIX ();

$ENV{'PATH'} = '/sbin:/usr/sbin:/bin:/usr/bin';

die "Usage: $0 ( cwe | ewc ) [sleeptime]\n" unless @ARGV == 1 or @ARGV == 2;
my $close_wait_exit;
   if ($ARGV[0] eq 'cwe') { $close_wait_exit = 1 }
elsif ($ARGV[0] eq 'ewc') { $close_wait_exit = 0 }
else { die "'$ARGV[0]' not 'cwe' nor 'ewc'\n"; }

my $st = 0; $st = int $ARGV[1] if @ARGV == 2; $st = 2 if $st <= 0;

$| = 1;

$SIG{HUP} = 'IGNORE';

print "sleeping 1 sec (rerun multiple times, observe delays)\n";
sleep 1;
if ($close_wait_exit) {
    print "closing fd's then sleep $st sec before exit\n";
    POSIX::close(0); POSIX::close(1);
    POSIX::close(2); POSIX::setsid(); # setsid->eperm :O (strace'd)
    sleep $st;
    POSIX::_exit(11);
}
# else
print "forking child. parent exits. child sleeps $st sec\n";
POSIX::_exit(22) if fork;
print "in child\n";
sleep $st;
print "child exit\n";
POSIX::_exit(33);
