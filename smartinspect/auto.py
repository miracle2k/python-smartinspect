"""Quickstart module that'll prepare a session for you ready to use.

>>> from smartinspect.auto import *
>>> si.enabled = True                   # connect
>>> si_main.log('app started')          # start logging

If you're not happy with the default TCP connection, feel free to
change it before enabling:

>>> from smartinspect.auto import *
>>> si.connections = 'mem()'
>>> si.enabled = True
"""

import sys
from smartinspect import SmartInspect

__all__ = ('si', 'si_main',)

si = SmartInspect(sys.argv[0])
si.connections = 'tcp()'
si.enabled = False
si_main = si.add_session('Main', True)