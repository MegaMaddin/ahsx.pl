ahsx.pl - The Apache HTTPD SSL Extractor
========================================

Did you ever had the problem, that your colleagues killed the SSL
directory and you didn't have a backup? Or did your prior BOFH has
left and you have to restart httpd with a super duper secret password
protected private key?

Relax and lean back, ahsx.pl can help. For all the others, the day
will come...

Usage of ahsx.pl
================

ahsx.pl can extract and recover x509 certificates and the RSA private
keys directly from a coredump. To achive a coredump, there are many
possibilities, for example via gdb or gcore, which is gdb-wrapper
script:

    [root@server tmp]# gcore 10751
    Saved corefile core.10751

For simplicity and the case that gdb or gcore is not available, the
cdu.pl (core dump utility) exists. It behaves almost as gcore, but
dumps the memory directly via /proc/$pid/mem:

    [root@server tmp]# perl cdu.pl 10751
    start reading data from /proc/10751/mem via /proc/10751/maps and
    dumping to /tmp/core.10751

If you have achived your coredump you can start ahsx.pl and with
your newly created dump, ahsx.pl will do the rest and inform you if 
it found a certificate or a key:

    [root@server tmp]# perl ahsx.pl < /tmp/core.10751 
    Found 2 certificates and 1 private key
    Written them to the following files:
    6292349_1193_der.key
    3145728_893_der.crt
    9439270_893_der.crt
