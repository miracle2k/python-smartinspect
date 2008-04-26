"""
Is testing:
    * Process Flow tracking under heavy recursion
    * Watches
    * Different ways of logging multiple values at once

Based on:
http://shootout.alioth.debian.org/gp4/benchmark.php?test=recursive&lang=python&id=0
"""

from smartinspect.auto import *

import sys

@si_main.track
def Ack(x, y):
    si_main.log_value('x, y', [x, y])
    si_main.watch('x', x)
    si_main.watch('y', y)
    if x == 0: return y+1
    if y == 0: return Ack(x-1, 1)
    return Ack(x-1, Ack(x, y-1))

@si_main.track
def Fib(n):
    si_main.log_value('n', n)
    if n < 2: return 1
    return Fib(n-2) + Fib(n-1)

@si_main.track
def Tak(x, y, z):
    si_main.log_value('x, y', [x, y])
    si_main.log_value('z', z)
    if y < x: return Tak( Tak(x-1,y,z), Tak(y-1,z,x), Tak(z-1,x,y) )
    return z

@si_main.track
def TakFP(x, y, z):
    si_main.log([x, y, z])
    if y < x: return TakFP( TakFP(x-1.0,y,z), TakFP(y-1.0,z,x), TakFP(z-1.0,x,y) )
    return z

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Expected one argument."
        sys.exit(1)
    si.connections = sys.argv[1]
    si.enabled = True
    si.level = Level.Debug

    #### logging start ####

    from sys import argv, setrecursionlimit
    setrecursionlimit(20000)

    Ack(3, 2)
    Tak(3*2, 2*2, 2)
    Fib(3)
    TakFP(3.0, 2.0, 1.0)

    #### logging end ####

    from __init__ import mem2stdout
    mem2stdout(si)