"""
Testing:
    * Various ways to specify log levels
    * Limit log output by level
    * Manual initialization without using the auto module
"""

import smartinspect
import sys

if len(sys.argv) != 2:
    print "Expected one argument."
    sys.exit(1)

si = smartinspect.SmartInspect('loglevel test script')
si.connections = sys.argv[1]
si.enabled = True

logger = si.add_session('Main', True)

## start logging

# run the following code with a different filter for all
# available log levels
for level in sorted([l for l in smartinspect.Level]):
    # use this level as a filter
    si.level = level

    # output information about the current loop iteration; use the Control
    # level to ensure it will always be logged. Note that the separator is
    # level-based too.
    logger.log_separator(level=smartinspect.Level.Control)
    logger.log('Current Level: %s'%si.level.name(), level=smartinspect.Level.Control)
    logger.add_checkpoint()

    # various log levels
    logger.log_debug("debug message")
    logger.log_verbose("verbose message")
    logger.log_message("message-level message")
    logger.log_warning("warning message")
    logger.log_error("error message")
    logger.log_fatal("fatal message")

    # call the generic log method directly (not recommended)
    logger.log("debug message", level=smartinspect.Level.Debug)
    logger.log("verbose message", level=smartinspect.Level.Verbose)
    logger.log("message-level message", level=smartinspect.Level.Message)
    logger.log("warning message", level=smartinspect.Level.Warning)
    logger.log("error message", level=smartinspect.Level.Error)
    logger.log("fatal message", level=smartinspect.Level.Fatal)

    # log a value
    logger.log_value("current level", level, level=smartinspect.Level.Debug)
    logger.log_value("current level", level, level=smartinspect.Level.Verbose)
    logger.log_value("current level", level, level=smartinspect.Level.Message)
    logger.log_value("current level", level, level=smartinspect.Level.Warning)
    logger.log_value("current level", level, level=smartinspect.Level.Error)
    logger.log_value("current level", level, level=smartinspect.Level.Fatal)

    # log with colors for a change
    logger.log_message("i feel blue", color=(0, 0, 255))
    logger.log_message("i feel blue", color=(0, 0, 255, 0))

    # special log methods
    logger.log_assert(True==False, "gravitation still intact")
    try:
        raise Exception("random error")
    except:
        logger.log_exception("exception occured")


## logging done
from __init__ import mem2stdout
mem2stdout(si)