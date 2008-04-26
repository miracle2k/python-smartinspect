"""
Based on:
http://shootout.alioth.debian.org/gp4/benchmark.php?test=mandelbrot&lang=python&id=3
"""

from smartinspect.auto import *

import sys

@si_main.track
def mandelbrot(size):
    #cout = sys.stdout.write
    iter = 50
    limit = 2.
    fsize = float(size)
    xr_size = xrange(size)
    xr_iter = xrange(iter)
    bit_num = 7
    byte_acc = 0

    #cout("P4\n%d %d\n" % (size, size))

    for y in xr_size:
        si_main.log_value("y-loop", y)
        fy = 2j * y / fsize - 1j
        for x in xr_size:
            si_main.log_value("x-loop", x)
            z = 0j
            c = 2. * x / fsize - 1.5 + fy

            for i in xr_iter:
                si_main.log_value("i-loop", i)
                z = z * z + c
                if abs(z) >= limit:
                    break
            else:
                byte_acc += 1 << bit_num

            if bit_num == 0:
                si_main.log_debug("cout %s" % byte_acc)
                #cout(chr(byte_acc))
                bit_num = 7
                byte_acc = 0
            else:
                bit_num -= 1

        if bit_num != 7:
            si_main.log_debug("cout %s" % byte_acc)
            #cout(chr(byte_acc))
            bit_num = 7
            byte_acc = 0

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Expected one argument."
        sys.exit(1)
    si.connections = sys.argv[1]
    si.enabled = True
    si.level = Level.Debug

    #### logging start ####

    si_main.clear_all()
    si_main.enter_process()
    try:
        mandelbrot(5)
    finally:
        si_main.leave_process()

    #### logging end ####

    from __init__ import mem2stdout
    mem2stdout(si)