#!/usr/bin/perl
#
# cdu.pl - The Core Dump Utility
#
# Copyright (c) 2013 github@megamadding.org
# All rights reserved.
#
# Author: <github@megamaddin.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

use strict;
use warnings;

my $pid = $ARGV[0] || $$;
my $file = $ARGV[1] || "/tmp/core.$pid";
my $mem = sprintf "/proc/%d/mem", $pid;
my $maps = sprintf "/proc/%d/maps", $pid;
my $ptrace = 0;

unless($$ == $pid) {
    $> == 0 || warn "You should better try this with root privileges or capability CAP_SYS_PTRACE set\n";
    require 'syscall.ph'; 
    # only ptrace()'ing processes are allowed to read /dev/$pid/mem, so attach to it
    # PTRACE_ATTACH = 16,
    (syscall(&SYS_ptrace, 16, $pid, 0, 0)) == -1 && die "Can't attach to process $pid: $!";
    # we've to wait for the attached process until it change his state to stopped (see man ptrace(2))
    wait();
    $ptrace = 1;
}

printf "start reading data from %s via %s and dumping to %s\n", $mem, $maps, $file;

open(my $memfh, '<', $mem) or die "Can't open $mem for reading: $!";
open(my $mapsfh, '<', $maps) or die "Can't open $maps for reading: $!";
open(my $fh, '>', $file) or die "Can't open $file for writing: $!";

while(my $line = <$mapsfh>) {
    # see fs/proc/task_mmu.c +232 ff.
    # %08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu %n
    my ($start, $end, $perm, $offset, $fd, $inode, $tag) = $line =~ m/([0-9a-f]+)-([0-9a-f]+)\s([rwxp-]+)\s([0-9a-f]+)\s([0-9a-f:0-9a-f]+)\s(\d+)\s+(.*)$/i;
    if(defined($perm) && $perm =~/r/) {
        no warnings "portable";
        seek($memfh, hex($start), 0);
        read($memfh, my $buf, hex($end)-hex($start));
        use warnings "portable";
        print $fh $buf;
    }
}

close($memfh);
close($mapsfh);
close($fh);

unless($$ == $pid && !$ptrace) {
    $> == 0 || warn "You should better try this with root privileges or capability CAP_SYS_PTRACE set\n";
    # detach from traced process
    # PTRACE_DETACH = 17,
    (syscall(&SYS_ptrace, 17, $pid, 0, 0)) == -1 && die "Can't detach from process $pid: $!";
}
