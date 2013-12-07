#!/usr/bin/perl
#
# ahsx.pl - The Apache HTTPD SSL Extractor
#
# Copyright (c) 2013 github@megamadding.org
# All rights reserved.
#
# Author: <github@megmaddin.org>
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

use Data::Dumper qw(Dumper);

my $debug = $ENV{'DEBUG'} || 0;
my $size = 1024;
my $buf;
my @window;
my $w_size = 6;

my $fh;
my $file = $ARGV[0];
my $fsize;
my $offset = 0;
my $wheeler = 0;
my @found_certs;
my @found_keys;

if(defined($file) && -r $file) {
    open($fh, '<', $file) or die "Can't open $file for reading: $!\n";
    $fsize = (stat($file))[7];
    $| = 1;
} else {
    $fh = \*STDIN;
}

while(my $read_bytes = read($fh, $buf, $size)) {
    $offset += $read_bytes;
    my $ws = unpack('H*', $buf);
    @window = $ws =~ m/[0-9a-z]{2}/gi;
    # crappy sliding window
    for(my $idx = 0; $idx <= scalar(@window)-$w_size; $idx++) {
        if(hex($window[$idx]) == hex('0x30') && hex($window[$idx+1]) == hex('0x82')) {
            my $off = $offset - $size + $idx;
            printf "probably found SEQUENCE header at offset 0x%x, idx=0x%x, idx+1=0x%x, idx+4=0x%x, idx+5=0x%x\n",$off, hex($window[$idx]), hex($window[$idx+1]), hex($window[$idx+4]), hex($window[$idx+5]) if $debug;
            if((hex($window[$idx+4]) == hex('0x30') && hex($window[$idx+5]) == hex('0x82')) ||
               (hex($window[$idx+4]) == hex('0x02') && hex($window[$idx+5]) == hex('0x01'))) {
                my $type = hex($window[$idx+4]) == hex('0x30') ? 'crt' : 'key';
                # length is 4 bytes after SEQUENCE header + SEQUENCE header
                my $len = hex($window[$idx+2].$window[$idx+3]) + 4;
                printf "found a %s with a length of %d bytes, trying to extract...\n", $type, $len unless($fsize);
                my $obj = extract($fh, $off, $len, $offset);
                write_der($off.'_'.$len.'_der.'.$type, $obj) if(defined($obj));
            }
        }
    }
    # slide back window_size and read new chunk;
    $offset -= $w_size;
    # but only if we know that there are more than window_size bytes left in $fh
    seek($fh, $offset, 0) unless($read_bytes <= $w_size);
    progress_bar($fsize, $offset, 5) if(defined($fsize));
}

if(defined($fsize)) {
    printf("Found %d certificate%s and %d private key%s\n", scalar(@found_certs),
                                                            (scalar(@found_certs) > 1 || scalar(@found_certs) == 0 ? 's' : ''),
                                                            scalar(@found_keys),
                                                            (scalar(@found_keys) > 1 || scalar(@found_keys) == 0 ? 's' : ''));
    print "Written them to the following files:\n", join("\n", @found_keys, @found_certs), "\n" if(scalar(@found_certs) >= 1 || scalar(@found_keys) >= 1);
}

sub progress_bar {
    my $operation_size = shift;
    my $progress = shift;
    my $resolution = shift;
    my $percentage = int($progress * 100 / $operation_size);
    my $blocks = int($percentage/$resolution); 
    my @wheel = ('/','|','\\', '-');
    $wheeler = $wheeler >= $#wheel ? 0 : ++$wheeler;

    printf("| %-2d %% | %s %-*s |\r", $percentage, $wheel[$wheeler], (100 / $resolution), '#'x$blocks);
}

sub write_der {
    my $filename = shift;
    my $data = shift;
    open(my $der, '>', $filename) || die "can't write DER to file: $!\n";
    print $der $data;
    close($der);
    $filename =~ /key/ ? push(@found_keys, $filename) : push(@found_certs, $filename);
    printf "written DER to file %s\n", $filename unless($fsize);
}

sub extract {
    my $fh = shift;
    my $offset = shift;
    my $len = shift;
    my $cur_offset_in_file = shift;
    my $obj;
    my $bytes = 0;

    # set filemarker to the offset of our object
    seek($fh, $offset, 0);
    $bytes += read($fh, $obj, $len);
    unless($bytes == $len) {
        $obj = undef;
        warn "bytes != len - something went wrong, undefining obj\n";
    }
    # reset filemarker to the previous position
    seek($fh, $cur_offset_in_file, 0);
    return($obj);
}
