Dependencies:
-------------
    * Python 2.5
	* py.test for running the tests
	
Examples:
---------

Simple Hello World:

>>> from smartinspect.auto import *
>>> si.enabled = True
>>> si.log_debug("hello world!")

Manual initialization, without using the smartinspect.auto module:

>>> from smartinspect import *
>>> si = SmartInspect("myapp")
>>> si.enabled = True
>>> logger = si.add_session("main")
>>> logger.log_debug("hello world!")

Manually logging process flow:

>>> def append(self, obj):
>>>     logger.enter_method("append", self)
>>>     try:
>>>         pass   # so something
>>>     finally:
>>>         logger.leave_method("append", self)


Logging process flow using the decorator:

>>> @logger.track
>>> def append(self, obj):
>>>     pass   # so something

Todo:
-----

	* FileProtocol, TextProtocol
	* Integration with Python Logging
	* @track should log function arguments