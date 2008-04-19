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

import os
from smartinspect import SmartInspect, Level

__all__ = ('si', 'si_main', 'Level')

si = SmartInspect(os.path.basename(os.sys.argv[0]))
si.connections = 'tcp()'
si.enabled = False
si_main = si.add_session('Main', True)