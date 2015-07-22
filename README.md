python-smartinspect
===================

Dependencies:
-------------
  * Python 2.5
  * py.test for running the tests

Examples:
---------

__Simple Hello World:__

```python
>>> from smartinspect.auto import *
>>> si.enabled = True
>>> si.log_debug("hello world!")
```

__Manual initialization, without using the smartinspect.auto module:__

```python
>>> from smartinspect import *
>>> si = SmartInspect("myapp")
>>> si.enabled = True
>>> logger = si.add_session("main")
>>> logger.log_debug("hello world!")
```

__Logging via tcp to a running SmartInspect Console on localhost__
```python
>>> import smartinspect
>>> si = smartinspect.SmartInspect("myapp")
>>> si.connections = "tcp()"
>>> si.enabled = True
>>> logger = si.add_session("main")
>>> logger.log_debug("hello world!")
```


__Manually logging process flow:__

```python
>>> def append(self, obj):
>>>     logger.enter_method("append", self)
>>>     try:
>>>         pass   # so something
>>>     finally:
>>>         logger.leave_method("append", self)
```


__Logging process flow using the decorator:__

```python
>>> @logger.track
>>> def append(self, obj):
>>>     pass   # so something
```

Todo:
-----

  * FileProtocol, TextProtocol
  * Integration with Python Logging
  * @track should log function arguments
