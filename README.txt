Dependencies:
	* py.test for running the tests
	
Examples:

>>> from smartinspect.auto import *
>>> si.enabled = True
>>> si.log_debug("hello world!")


>>> from smartinspect import *
>>> si = SmartInspect("myapp")
>>> logger = si.add_session("main")
>>> logger.log_debug("hello world!")


>>> def append(self, obj):
>>>     logger.enter_method("append", self)
>>>     try:
>>>         pass   # so something
>>>     finally:
>>>         logger.leave_method("append, self)


>>> @logger.track
>>> def append(self, obj):
>>>     pass   # so something