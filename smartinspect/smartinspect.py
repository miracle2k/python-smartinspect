"""A SmartInspect Python Library.

Port of SmartInspect.pas (from SmartInspect Professional v2.3.3.7025)

NOTE: Many things in here have not yet been tested at all. This code is alpha
quality in a very real sense. You have been warned.

Not all the features have been implemented yet. In particular, the file-based
protocols are missing.

Other Compatibility Notes:

    * Identifers have been changed to conform with the Python style guide. In
      some instances it made sense to slightly modify implementations, say
      using a property instead of a simple get-method.

    * Due to the dynamic nature of Python the number of Log*, Watch* etc.
      methods could be drastically reduced. In particular, we are taking
      advantage of Python's optional keyword arguments, simple string
      formatting and loose-typing.

    * The events of the ``SmartInspect`` class (OnWatch, OnLogEntry, ...) do
      not exist. If needed, implementing such callbacks could be considered.

    * OnError has also been removed and deserves a special mention - instead,
      exceptions raised in methods like ``load_connections`` are passed through
      to the caller directly.

    * While the ``ViewerContext`` class exists to allow custom contexts, most
      of it's default subclasses are not implemented, as it is unclear what
      they are good for - their respective log functions seem to do their own
      view formatting.

   * Instead of the ``BufferedStream`` class we use the builtin buffering of
     Pythons ``open()`` function, but apparently whether it works or not
     depends partly on the underlying OS implementation (see the comments on
     (fixed) the Python Bug #603724).

   * The High-resolution clock is not supported on any platform.

   * ``TrackMethod()`` is replaced by Python decorators (hurray for
     first-class functions!)

   * Comments are largely missing so far.
"""

from __future__ import with_statement
import os, sys
import re
import socket
import struct
import threading, thread
import datetime, time
import StringIO

try:
    from pyutils.xtypes import ValueEnum as Enum
except:
    from __enum import ValueEnum as Enum


__all__ = (
    'SmartInspect', 'Session',
    'Level',
)

################################################################################
## Global constants.
################################################################################

VERSION = '0.01 for 2.3.3.7025'
TCP_CLIENT_BANNER = 'SmartInspect Python Library v' + VERSION;

DEFAULT_COLOR = (0x05, 0x00, 0x00, 0xff,)   # clWindow / COLOR_WINDOW
MAGIC_LOG_STRING = 'SILF'
DEFAULT_TEXT_PATTERN = '[%timestamp%] %level%: %title%'

CAPTION_NOT_FOUND_MSG = 'No protocol could be found with the specified caption'
SOCKET_CLOSED_MSG = 'Connection has been unexpectedly closed'
INVALID_SOCKET_MSG = 'Invalid socket handle'
CONNECTION_ESTABLISHED_MSG = 'Connection already established'
TIMEOUT_MSG = 'Timed out while trying to connect'
NO_CONNECTION_MSG = 'No socket connection established'
PROTOCOL_CONNECTED_MSG = 'This protocol is currently connected. ' +\
                         'Please disconnect before you change any ' +\
                         'protocol specific options.'



################################################################################
## Exception classes.
################################################################################

class SmartInspectError(Exception): pass

class LoadConnectionsError(SmartInspectError):
    def __init__(self, filename):
        self.filename = filename

class LoadConfigurationsError(SmartInspectError):
    def __init__(self, filename):
        self.filename = filename

class ProtocolError(SmartInspectError):
    """Error raised in Protocol-related code.

    References the ``Protocol`` instance directly, instead of storing
    it's name and options string, as in the Delphi implementation.
    """
    def __init__(self, message, protocol, *args, **kwargs):
        self.protocol = protocol
        super(ProtocolError, self).__init__(message, *args, **kwargs)

class InvalidConnectionsError(SmartInspectError): pass



################################################################################
## Enumerations.
################################################################################

class PacketType(Enum):
    """IDs as expected by SI console."""
    LogEntry = 4
    ControlCommand = 1
    Watch = 5
    ProcessFlow = 6

class LogEntryType(Enum):
    """IDs as expected by SI console."""
    Separator = 0
    EnterMethod = 1
    LeaveMethod = 2
    ResetCallstack = 3
    Message = 100
    Warning = 101
    Error = 102
    InternalError = 103
    Comment = 104
    VariableValue = 105
    Checkpoint = 106
    Debug = 107
    Verbose = 108
    Fatal = 109
    Conditional = 110
    Assert = 111
    Text = 200
    Binary = 201
    Graphic = 202
    Source = 203
    Object = 204
    WebContent = 205
    System = 206
    MemoryStatistic = 207
    DatabaseResult = 208
    DatabaseStructure = 209

class ViewerId(Enum):
    """IDs as expected by SI console."""
    None_ = -1
    Title = 0
    Data = 1
    List = 2
    ValueList = 3
    Inspector = 4
    Table = 5
    Web = 100
    Binary = 200
    HtmlSource = 300
    JavaScriptSource = 301
    VbScriptSource = 302
    PerlSource = 303
    SqlSource = 304
    IniSource = 305
    PythonSource = 206
    XmlSource = 307
    Bitmap = 400
    Jpeg = 401
    Icon = 402
    Metafile = 403

class SourceId(Enum):
    Html = 1
    Javascript = 2
    VbScript = 3
    Perl = 4
    Sql = 5
    Ini = 6
    Python = 7
    Xml = 8

class GraphicId(Enum):
    Bitmap = 0
    Jpeg = 1
    Icon = 2
    Metafile = 3

class ControlCommandType(Enum):
    ClearLog = 0
    ClearWatches = 1
    ClearAutoViews = 2
    ClearAll = 3
    ClearProcessFlow = 4

class WatchType(Enum):
    Char = 0
    String = 1
    Integer = 2
    Float = 3
    Boolean = 4
    Address = 5
    Timestamp = 6
    Object = 7

class ProcessFlowType(Enum):
    EnterMethod = 0
    LeaveMethod = 1
    EnterThread = 2
    LeaveThread = 3
    EnterProcess = 4
    LeaveProcess = 5

class Level(Enum):
    Debug = 0
    Verbose = 1
    Message = 2
    Warning = 3
    Error = 4
    Fatal = 5
    Control = 6

class FileRotate(Enum):
    None_ = 0
    Hourly = 1
    Daily = 2
    Weekly = 3
    Monthly = 4


################################################################################
## Core classes (packet & packet types).
################################################################################

class Packet(object):
    """Base class for all packets."""
    def __init__(self):
        self.level = Level.Message
        self._data = StringIO.StringIO()

    def _get_size(self):
        raise NotImplementedError()
    size = property(lambda s: s._get_size())

    def _get_packet_type(self):
        raise NotImplementedError()
    packet_type = property(lambda s: s._get_packet_type())

    def _get_data(self):
        return self._data
    def _set_data(self, value):
        if value:
            self._data = copy(value)
        else:
            self._data.truncate(size=0)
    data = property(_get_data, _set_data)

    @property
    def has_data(self):
        return self._data and self._data.len > 0

class PacketQueue(object):
    """A queue of packet objects with auto byte-resizing functionality."""

    def __init__(self, backlog=None):
        self._data = []
        self._backlog = backlog   # maximum size
        self._size = 0

    def _set_backlog(self, value):
        self._backlog = value
        self._resize()
    backlog = property(lambda s: s._backlog, _set_backlog)

    def _resize(self):
        while self._backlog and self._size > self._backlog:
            self.pop()

    def clear(self):
        while self._data:
            self.pop()

    def push(self, packet):
        self._data.append(packet)
        self._size += packet.size
        self._resize()

    def pop(self):
        if len(self._data):
            p = self._data.pop(0)
            self._size -= p.size
            return p
        else:
            return None

class LogEntry(Packet):
    def __init__(self, log_entry_type, viewer_id):
        super(LogEntry, self).__init__()
        self._data = StringIO.StringIO()
        self.log_entry_type = log_entry_type
        self.viewer_id = viewer_id
        self.color = DEFAULT_COLOR
        self.thread_id = thread.get_ident()
        self.process_id = os.getpid()

    def _get_size(self):
        result = (48 +    # header
                    len(self.session_name) +
                    len(self.title) +
                    len(self.appname) +
                    len(self.hostname))
        if self.has_data:
            result += self.data.len
        return result

    def _get_packet_type(self):
        return PacketType.LogEntry

class ControlCommand(Packet):
    def __init__(self, control_command_type):
        super(ControlCommand, self).__init__()
        self.control_command_type = control_command_type
        self.level = Level.Control

    def _get_size(self):
        result = 8        # header
        if self.has_data:
            result += self.data.len
        return result

    def _get_packet_type(self):
        return PacketType.ControlCommand

class Watch(Packet):
    def __init__(self, watch_type):
        super(Watch, self).__init__()
        self.watch_type = watch_type

    def _get_size(self):
        result = (20 +       # header
                    len(self.name) +
                    len(self.value))
        return result

    def _get_packet_type(self):
        return PacketType.Watch

class ProcessFlow(Packet):
    def __init__(self, process_flow_type):
        super(ProcessFlow, self).__init__()
        self.process_flow_type = process_flow_type
        self.thread_id = thread.get_ident()
        self.process_id = os.getpid()

    def _get_size(self):
        result = (28 +       # header
                    len(self.title) +
                    len(self.hostname))
        return result

    def _get_packet_type(self):
        return PacketType.ProcessFlow


################################################################################
## Protocols and related classes.
################################################################################

class Formatter(object):
    """Formatters are responsible for formatting and writing a packet."""
    def format(self, packet, stream):
        self.compile(packet)
        self.write(stream)

class BinaryFormatter(Formatter):
    """Stores log data in a fast binary format."""

    max_capacity = 10 * 1024 * 1024

    def __init__(self):
        self._stream = StringIO.StringIO()
        self._size = 0

    def _reset_stream(self):
        if self._size > BinaryFormatter.max_capacity:
            # Reset the stream capacity if the previous packet
            # was very big. This ensures that the amount of memory
            # can shrink again after a big packet has been sent.
            self._stream.truncate(0)
        else:
            # Only reset the position. This should ensure better
            # performance since no reallocations are necessary.
            self._stream.pos = 0

    def _write_string(self, s):
        if isinstance(s, unicode):
            s = s.encode('utf-8')
        self._stream.write(s)
    def _write_long(self, i):
        # store as Delphi Integer (32bit signed, little endian)
        self._stream.write(struct.pack('l', i))
    def _write_ulong(self, i):
        # store as Delphi Cardinal (32bit unsigned, little endian)
        self._stream.write(struct.pack('l', i))
    def _write_word(self, i):
        # store as Delphi Word (16bit unsigned, little endian)
        self._stream.write(struct.pack('H', i))
    def _write_datetime(self, d):
        # Delphi TDatetime is 8-byte double:
        # TDateTime := UnixTimestamp / SecsPerDay * UnixTimestamp(01/10/1070)
        tdatetime = time.mktime(d.timetuple()) / 86400 + 25569.0
        self._stream.write(struct.pack('d', tdatetime))
    def _write_color(self, c):
        # c is a 3 or 4-tuple; see module doc section on colors for more info
        e = (list(c) + [0])[:4]
        if len(e) != 4: raise SmartInspectError('Not a valid color: %s'%c)
        self._write_string("".join(map(lambda n: struct.pack('B', n), e)))

    def write(self, stream):
        """Writes a previously compiled packet to the supplied stream."""
        if self._size > 0:
            # hack: store target stream locally so we can use _write_* methods
            __self_stream = self._stream
            self._stream = stream
            # write packet header to output
            self._write_word(self._packet.packet_type)
            self._write_long(self._size)
            # copy local, compiled data to output stream as packet body
            __self_stream.pos = 0
            # read max size as stream might not have been reset!
            stream.write(__self_stream.read(self._size))
            # switch streams back
            self._stream = __self_stream

    def compile(self, packet):
        self._reset_stream()
        self._packet = packet

        if packet.packet_type == PacketType.LogEntry:
            self._compile_log_entry()
        elif packet.packet_type == PacketType.Watch:
            self._compile_watch()
        elif packet.packet_type == PacketType.ControlCommand:
            self._compile_control_command()
        elif packet.packet_type == PacketType.ProcessFlow:
            self._compile_process_flow()

        self._size = self._stream.pos
        return self._size + 6    # packet header size: 6 bytes

    def _compile_control_command(self):
        control_command = self._packet
        stream = self._stream

        # header
        self._write_long(control_command.control_command_type)
        if control_command.has_data: self._write_long(control_command.data.len)
        else: self._write_long(0)

        # values
        if control_command.has_data:
            stream.write(control_command.data.read())
            control_command.data.pos = 0

    def _compile_log_entry(self):
        log_entry = self._packet
        stream = self._stream

        # header
        self._write_long(log_entry.log_entry_type)
        self._write_long(log_entry.viewer_id)
        self._write_long(len(log_entry.appname))
        self._write_long(len(log_entry.session_name))
        self._write_long(len(log_entry.title))
        self._write_long(len(log_entry.hostname))
        if log_entry.has_data: self._write_long(log_entry.data.len)
        else: self._write_long(0)
        self._write_ulong(log_entry.thread_id)
        self._write_ulong(log_entry.process_id)
        self._write_datetime(log_entry.timestamp)
        self._write_color(log_entry.color)

        # values
        self._write_string(log_entry.appname)
        self._write_string(log_entry.session_name)
        self._write_string(log_entry.title)
        self._write_string(log_entry.hostname)
        if log_entry.has_data:
            stream.write(log_entry.data.read())
            log_entry.data.pos = 0

    def _compile_process_flow(self):
        process_flow = self._packet
        stream = self._stream

        # header
        self._write_long(process_flow.process_flow_type)
        self._write_long(len(process_flow.title))
        self._write_long(len(process_flow.hostname))
        self._write_ulong(process_flow.process_id)
        self._write_ulong(process_flow.thread_id)
        self._write_datetime(process_flow.timestamp)

        # values
        self._write_string(process_flow.title)
        self._write_string(process_flow.hostname)

    def _compile_watch(self):
        watch = self._packet
        stream = self._stream

        # header
        self._write_long(len(watch.name))
        self._write_long(len(watch.value))
        self._write_long(watch.watch_type)
        self._write_datetime(watch.timestamp)

        # values
        self._write_string(watch.name)
        self._write_string(watch.value)

class TextFormatter(Formatter):
    def __init__(self):
        self._parser = PatternParser()

    def compile(self, packet):
        if packet.packet_type == PacketType.LogEntry:
            self.line = (self._parser.expand(packet) + "#13#10").encode('utf-8')
            return len(line)
        else:
            self.line = ''
            return 0

    def write(self, stream):
        if self.line:
            stream.write(line)

    @property
    def indent(self):
        return self._parser.indent

    @property
    def pattern(self):
        return self._parser.indent

class ProtocolCommand(object):
    def __init__(self, action, state):
        self.action = action
        self.state = state

class ProtocolOptions(object):
    """Manages a set of options for a protocol instance. The instance is
    expected to store it's copy of the options in an attribute named
    ``_options``.

    This replaces the BuildOptions/LoadOptions methods on ``Protocol``
    classes in the Delphi implementation.
    """

    def __init__(self, onchange=None):
        self._options = {}
        self.onchange = onchange

    def __get__(self, instance, owner):
        # options property is read, return an options instance linking to
        # the protocol object this was accessed by (``instance``).
        return ProtocolOptions._OptionsImpl(instance, self.onchange)

    def __set__(self, instance, value):
        # something is assigned to the options property
        if isinstance(value, dict):
            pass
        elif value is None:
            value = {}
        elif isinstance(value, ProtocolOptions):
            value = value._options
        else:
            raise SmartInspectError(
                    'Can''t assign a "%s" to protocol options.' % type(value))

        # update our own values
        for k, v in value.items():
            setattr(instance.options, k, v)

    class _OptionsImpl(object):
        # The actual options "attribute access" implementation. The outer
        # descriptor creates an instance of this with a link to the correct
        # ``Protocol`` instance on "get".

        def __init__(self, protocol, onchange):
            self._onchange = onchange
            self.__dict__['_protocol'] = protocol # __setattr__ already requires this
            if not hasattr(protocol, '_options'):
                protocol._options = {}

        def _validate_option(self, option):
            if not option in self._protocol.valid_options.keys():
                raise SmartInspectError(u'Option "%s" not available for protocol "%s"' % \
                            (option, self._protocol.name,));

        def __setattr__(self, key, value):
            if key.startswith('_'):
                return object.__setattr__(self, key, value)
            else:
                with self._protocol._lock:
                    if self._protocol.connected:
                        raise SmartInspectError(PROTOCOL_CONNECTED_MSG)

                    self._validate_option(key)
                    if value != self._protocol._options.get(key, None):
                        self._protocol._options[key] = value
                        # note this is only called on an actual change
                        if self._onchange:
                            self._onchange(self._protocol)

        def __getattr__(self, key):
            with self._protocol._lock:
                self._validate_option(key)
                return self._protocol._options.get(
                    key, self._protocol.valid_options[key])

        def __iter__(self):
            for option in self._protocol.valid_options.keys():
                yield option

        def reset(self):
            """Reset to default values."""
            # clearing the dict works, we are just storing the changed values
            self._protocol.options = {}
            if self._onchange:
                self._onchange(self._protocol)


class Protocol(object):
    """A protocol is responsible for the transport of packets."""

    valid_options = {'level': Level.Debug,
                     'backlog': 0,
                     'flushon': Level.Error,
                     'reconnect': False,
                     'keepopen': True, \
                     'caption': None}

    def _options_changed(self):
        # default ``caption`` option to protocol name
        if (self.options.caption is None) and (type(self).name is not None):
            self.options.caption = type(self).name
        if self.options.backlog <= 0:
            self.options.keepopen = True
    options = ProtocolOptions(lambda s: s._options_changed())

    def __init__(self):
        self._lock = threading.RLock()
        self._queue = PacketQueue()
        self.connected = False
        self.options.reset()        # will cause a validation

    def _internal_reconnect(self):
        self._internal_connect()

    def _internal_dispatch(self, command):
        # empty by default
        pass

    def connect(self):
        with self._lock:
            if not self.connected and self.options.keepopen:
                try:
                    self._internal_connect()
                    self.connected = True
                except Exception, e:
                    self.reset()
                    raise e

    def reconnect(self):
        try:
            self._internal_reconnect()
            self.connected = True
        except:
            # ignore reconnect exceptions
            pass

    def disconnect(self):
        with self._lock:
            if self.connected:
                try:
                    self.reset()
                except Exception, e:
                    raise ProtocolError(str(e), self)

    def reset(self):
        self._queue.clear()
        self._connected = False
        self._internal_disconnect()

    def dispatch(self, command):
        with self._lock:
            if self.connected:
                try:
                    self._internal_dispatch(command)
                except Exception, e:
                    raise ProtocolError(str(e), self)

    def forward_packet(self, packet, disconnect):
        if not self.connected:
            if not self.options.keepopen:
                self._internal_connect()
                connected = True
            else:
                self.reconnect()

        if self.connected:
            self._internal_write_packet(packet)
            if disconnect:
                self.connected = False
                self._internal_disconnect()

    def write_packet(self, packet):
        with self._lock:
            if packet.level < self.options.level:
                return

            if self.connected or self.options.reconnect or \
                    not self.options.keepopen:
                try:
                    skip = False

                    if self.options.backlog > 0:
                        if packet.level >= self.options.flushon and \
                            packet.level <> PacketLevel.Control:
                                p = self._queue.pop()
                                while p:
                                    try:
                                        self.forward_packet(p, False)
                                    finally:
                                        p.release()
                                    p = self._queue.pop()
                        else:
                            self._queue.push(packet)
                            skip = True

                    if not skip:
                        self.forward_packet(packet, not self.options.keepopen)
                except Exception, e:
                    self.reset()
                    raise ProtocolError(str(e), self)

class MemoryProtocol(Protocol):
    name = "mem"

    valid_options = dict(Protocol.valid_options)
    valid_options.update({
        'astext': False,
        'maxsize': 2048,
        'pattern': DEFAULT_TEXT_PATTERN,
        'indent': False})

    def _options_changed(self):
        super(MemoryProtocol, self)._options_changed()
        # use a formatter fitting for the selection setting
        if self.options.astext:
            self.formatter = TextFormatter()
            self.formatter.pattern = self.options.pattern
            self.formatter.indent = self.options.indent
        else:
            self.formatter = BinaryFormatter()

    def _internal_connect(self):
        self.queue = PacketQueue()
        self.queue.size = self.options.maxsize

    def _internal_disconnect(self):
        self.queue.clear()

    def _internal_dispatch(self, command):
        if not command:
            return

        if hasattr(command.state, 'write'):
            s = command.state

            if self.options.astext:
                s.write('\xef\xbb\xbf')  # bom header
            else:
                s.write(MAGIC_LOG_STRING)

            packet = self.queue.pop()
            while packet:
                self.formatter.format(packet, s)
                packet = self.queue.pop()

    def _internal_write_packet(self, packet):
        self.queue.push(packet)


class TcpProtocol(Protocol):
    name = "tcp"

    valid_options = dict(Protocol.valid_options)
    valid_options.update({'host': '127.0.0.1',
                          'port': 4228,
                          'timeout': 30000})

    def __init__(self):
        super(TcpProtocol, self).__init__()
        self.formatter = BinaryFormatter()

    def _internal_connect(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.options.timeout/1000.0)
        self._socket.connect((self.options.host, self.options.port,))
        self._buffer = self._socket.makefile('rw', bufsize=0x2000)

        # exchange banners
        self._buffer.readline()
        self._buffer.write("%s\n"%TCP_CLIENT_BANNER)

    def _internal_write_packet(self, packet):
        # let the formatter write directly to the tcp stream
        self.formatter.format(packet, self._buffer)
        self._buffer.flush()

        # read (and wait for) the server answer
        x = self._buffer.read(2)
        if len(x) <> 2:
        #if len(self._buffer.read(2)) <> 2:
            # We couldn't read the entire answer from the server, but the
            #  Read method didn't raise an exception. This means that the
            # socket connection has been normally closed by the server,
            # but this shouldn't occur while trying to read the answer!
            raise ESmartInspectError.Create(SOCKET_CLOSED_MSG);

    def _internal_disconnect(self):
        self._socket.close()

class Protocols(object):
    """Globally manage a list of available protocols.

    Thread-safe.

    Replaces the ProtocolFactory class of the Delphi implementation.
    """
    _table = {
        'mem': MemoryProtocol,
        'tcp': TcpProtocol
        # Not yet supported
        # ('file', FileProtocol)
        # ('text', TextProtocol)
    }
    _lock = threading.RLock()

    @classmethod
    def get(cls, name, options=None):
        with cls._lock:
            result = cls._table.get(name, False)()
            if not result:
                raise SmartInspectError(u'Protocol "%s" not found'%name)
        if options:
            result.options = options
        return result

    @classmethod
    def register(cls, name, klass):
        if name and klass:
            with cls._lock:
                cls._table[name] = klass


################################################################################
## Public interface clasess
################################################################################

def default_level_to_parent(func):
    """Decorator used by log methods that have an optional ``level`` argument
    which should fallback to the instance's default if missing. For use within
    ``Session``.

    It's rather complex considering it only saves us one line within each
    method it's applied to (the line would like like this:
    ``if not level: level = self._parent.level``).

    Note: Currently this requires ``level`` to be passed as a keyword argument.
    Using introspection we could make it work for positional arguments as well.

    Instead of using this we could attempt to fallback to the default log level
    at a later moment before sending, in a common method, but this is difficult
    for a number of reasons:
        * Some methods need to validate that a certain level is below the
          treshold (see also ``if_is_on``), while other's don't - but all of
          them want to use the default level (e.g. see ``reset_callback``).
        * In addition, for thread-safety reasons the ``is_on()`` check should
          use the same level than the packet will then actually use, which
          means the level to use (and therefore whether to use the default) has
          to be determined before that.
        * Sometimes we have to send multiple packets (e.g. ``enter_method``)
    """
    def wrapper(self, *args, **kwargs):
        if kwargs.get('level', None) is None:
            kwargs['level'] = self.parent.defaultlevel
        return func(self, *args, **kwargs)
    return wrapper

def if_is_on(func):
    """Only runs the decorated method after passing the ``level`` keyword
    argument successfully through ``is_on``. For use within ``Session``.
    """
    def wrapper(self, *args, **kwargs):
        if self.is_on(kwargs.get('level')):
            return func(self, *args, **kwargs)
    return wrapper

class Session(object):
    def __init__(self, parent, name):
        self._namelock = threading.RLock()
        self._checkpointlock = threading.RLock()
        self._counterlock = threading.RLock()

        self.parent = parent
        self.name = name
        self._checkpointcounter = 0
        self.active = True

        self._counters = {}

    def set_name(self, value):
        with self._namelock:
            if value <> self.name:
                if self.is_stored:
                    self.parent.uddate_esssion(self, value, self.name)
                self.name = value

    def is_on(self, level=None):
        """
        Returns ``True`` if information would be logged for a certain log
        level or ``False`` if not. If ``level`` is not passed the result
        can still vary depending on whether the session is active, or the
        parent ``SmartInspect`` instance enabled.

        Python port note: The Delphi version uses two overloaded versions
        of this method here, which we can replace by defaulting the
        ``level`` argument to ``None``.
        """
        return self.active and self.parent.enabled and (
                    level >= self.parent.level or level is None)



    def send_log_entry(self, level, title, log_entry_type, viewer_id,
                      color=None, data=None):
        entry = LogEntry(log_entry_type, viewer_id)
        entry.timestamp = self.parent.now()
        entry.level = level
        entry.title = title
        entry.color = color or DEFAULT_COLOR
        entry.session_name = self.name
        entry.data = data
        self.parent.send_log_entry(entry)

    def send_process_flow(self, level, title, process_flow_type):
        process_flow = ProcessFlow(process_flow_type)
        process_flow.timestamp = self.parent.now()
        process_flow.level = level
        process_flow.title = title
        self.parent.send_process_flow(process_flow)

    def send_watch(self, level, name, value, watch_type):
        watch = Watch(watch_type)
        watch.timestamp = self.parent.now()
        watch.level = level
        watch.name = name
        watch.value = value
        self.parent.send_watch(watch)

    def send_control_command(self, control_command_type, data=None):
        control_command = ControlCommand(control_command_type)
        control_command.level = Level.Control
        control_command.data = data
        self.parent.send_control_command(control_command)

    def send_context():
        # TODO: just send_log_entry with a viewer instance as the data part
        raise NotImplementedError()



    @default_level_to_parent
    @if_is_on
    def log(self, title, level=None, color=None,
            entry_type=LogEntryType.Message):
        """
        A generic log method that allows full customization of all
        parameters involved.

        Python port note: This method is new - the Delphi implementation's
        log methods all call ``send_log_entry`` directly. In the Python
        version, those other methods all capture surplus arguments and pass
        them along to this generic version. I.e. the ``color`` argument (and
        possibly others in the future) are supported by all the log methods
        through this base implementation.

        While you can directly call this method if you want, it is
        recommended that you use the level- or type-specific methods like
        ``log_debug`` or ``log_value`` instead whenever possible.. In
        particular, those will also take care of sending the appropriate
        entry type for each specific log level (while the level determines
        what or when an entry is shown, the entry type determines *how* it is
        displayed, e.g. icon).
        """
        self.send_log_entry(level, "%s"%title, entry_type,
                            ViewerId.Title, color=color)

    def log_debug(self, *args, **kwargs):
        self.log(level=Level.Debug, entry_type=LogEntryType.Debug, *args, **kwargs)
    def log_verbose(self, *args, **kwargs):
        self.log(level=Level.Verbose, entry_type=LogEntryType.Verbose, *args, **kwargs)
    def log_message(self, *args, **kwargs):
        self.log(level=Level.Message, entry_type=LogEntryType.Message, *args, **kwargs)
    def log_warning(self, *args, **kwargs):
        self.log(level=Level.Warning, entry_type=LogEntryType.Warning, *args, **kwargs)
    def log_error(self, *args, **kwargs):
        self.log(level=Level.Error, entry_type=LogEntryType.Error, *args, **kwargs)
    def log_fatal(self, *args, **kwargs):
        self.log(level=Level.Fatal, entry_type=LogEntryType.Fatal, *args, **kwargs)



    def log_value(self, name, value, level=None, *args, **kwargs):
        # Depending on the datatype we may choose a different output format
        if isinstance(value, basestring):
            title = "%s = '%s'" % (name, value)
        else:
            title = "%s = %s" % (name, value)

        self.log(title, level=level,
                 entry_type=LogEntryType.VariableValue,
                 *args, **kwargs)



    @default_level_to_parent
    @if_is_on
    def log_separator(self, level=None):
        self.send_log_entry(level, '', LogEntryType.Separator, ViewerId.None_)

    def log_assert(self, condition, title):
        if self.is_on(Level.Error):
            if not condition:
                self.send_log_entry(Level.Error, title, LogEntryType.Assert,
                                    ViewerId.Title)

    def log_custom_file(self):
        raise NotImplementedError()  # TODO

    def log_custom_stream(self):
        raise NotImplementedError()  # TODO

    def log_object(self):
        raise NotImplementedError()  # TODO: RTTI/dir

    def log_memory_statistic(self):
        raise NotImplementedError()  # TODO

    def log_system(self):
        raise NotImplementedError()  # TODO

    def log_internal_error(self, title):
        self.log(title, level=Level.Error, entry_type=LogEntryType.InternalError)

    def log_exception(self, title='', exception=None, *args, **kwargs):
        """Log the exception given in ``exception`` argument, or the one
        currently handled, if any.
        """
        if self.is_on(Level.Error):
            if not exception:
                exception = sys.exc_info()[1]
                if exception is None:
                    self.log_internal_error('log_exception: No exception is currently handled')
                    return

            # TODO: this is dangerous, as we don't know what str() returns;
            # especially non-ascii error messages will create problems.
            # find a better way to convert to a string, e.g. see:
            # http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/444746
            msg = (title and title+': ' or '') + str(exception)
            self.log_error(msg, *args, **kwargs)

##    -- Hm, looks liek sys.last_value only works for unhandled exceptions.
##   --  That's not that helpful.
##    def log_last_exception(self, title=''):
##        """Log the last exception occured.
##
##        Python port note: Not available in the Delphi version. Do not
##        confuse with LogLastError(), which is Win32 API specific.
##        """
##        exception = getattr(sys, 'last_value', None)
##        if not exception:
##            self.log_internal_error('log_exception: No last exception found')
##        else:
##            return self.log_exception(title=title, exception=exception)


    @default_level_to_parent
    def reset_callstack(self, level=None):
        self.send_log_entry(level, '', LogEntryType.ResetCallstack)

    @default_level_to_parent
    @if_is_on
    def enter_method(self, name, level=None, instance=None):
        if instance:
            name = "%s.%s" %(type(instance).__name__, name)

        # send two packets, one log entry and one process flow entry
        self.send_log_entry(level, name, LogEntryType.EnterMethod,
                            ViewerId.Title);
        self.send_process_flow(level, name, ProcessFlowType.EnterMethod)

    @default_level_to_parent
    @if_is_on
    def leave_method(self, name, level=None, instance=None):
        if instance:
            name = "%s.%s" %(type(instance).__name__, name)

        # send two packets, one log entry and one process flow entry
        self.send_log_entry(level, name, LogEntryType.LeaveMethod,
                            ViewerId.Title);
        self.send_process_flow(level, name, ProcessFlowType.LeaveMethod)



    @default_level_to_parent
    @if_is_on
    def enter_thread(self, name, level=None):
        self.send_process_flow(level, name, ProcessFlowType.EnterThread)

    @default_level_to_parent
    @if_is_on
    def leave_thread(self, name, level=None):
        self.send_process_flow(level, name, ProcessFlowType.LeaveThread)

    @default_level_to_parent
    @if_is_on
    def enter_process(self, name=None, level=None):
        self.send_process_flow(level, name or self.parent.appname,
                             ProcessFlowType.EnterProcess)
        self.send_process_flow(level, 'Main Thread', ProcessFlowType.EnterThread)

    @default_level_to_parent
    @if_is_on
    def leave_process(self, name=None, level=None):
        self.send_process_flow(level, 'Main Thread', ProcessFlowType.LeaveThread)
        self.send_process_flow(level, name or self.parent.appname,
                             ProcessFlowType.LeaveProcess)

    def track(self, func):
        """Decorator to add process flow tracking around the wrapped function.

        Python lib specific (replaces ``TrackMethod``` utilities in Delphi).
        """
        def wrapped(*args, **kwargs):
            self.enter_method(func.__name__)
            try:
                return func(*args, **kwargs)
            finally:
                self.leave_method(func.__name__)
        return wrapped



    @default_level_to_parent
    @if_is_on
    def watch(self, name, value, level, watch_type=None):
        # Determine the value format and watch type to use, based on the type
        # of the value. The latter can be overridden via the ``watch_type``
        # argument, which can also affect formatting (e.g. WatchType.Address).
        if watch_type == WatchType.Address:
            tp = watch_type
            title = "%s" % id(value)
        # wtObject: currently unused by SmartInspect.pas
        elif isinstance(value, bool):
            tp = WatchType.Boolean
            title = value and 'True' or 'False'
        elif isinstance(value, int):
            tp = WatchType.Integer
            title = u"%s" % value
        elif isinstance(value, float):
            tp = WatchType.Float
            title = u"%s" % value
        elif isinstance(value, datetime.datetime):
            tp = WatchType.Float
            title = u"%s" % value  # TODO: use better format?
        else:
            tp = WatchType.String
            title = u"%s" % value

        self.send_watch(level, name, title, tp)

    @default_level_to_parent
    def add_checkpoint(self, level):
        with self._checkpointlock:
            self._checkpointcounter += 1
            counter = self._checkpointcounter

        if self.is_on(level):
            title = 'Checkpoint #%d' % self._checkpointcounter
            self.send_log_entry(level, title, LogEntryType.Checkpoint,
                                ViewerId.Title)

    def reset_checkpoint(self):
        with self._checkpointlock:
            self._checkpointcounter = 0



    @default_level_to_parent
    @if_is_on
    def inc_counter(self, name, level=None):
        with self._counterlock:
            self.counters[name] += 1
            value = self.counters[name]
        self.send_watch(level, name, value, WatchType.Integer)

    @default_level_to_parent
    @if_is_on
    def dec_counter(self, name, level=None):
        with self._counterlock:
            self.counters[name] -= 1
            value = self.counters[name]
        self.send_watch(level, name, value, WatchType.Integer)

    @default_level_to_parent
    @if_is_on
    def reset_counter(self, name):
        with self._counterlock:
            del counters[name]



    def send_custom_control_command():
        raise NotImplementedError()  # TODO

    def send_custom_log_entry():
        raise NotImplementedError()  # TODO

    def send_custom_process_flow():
        raise NotImplementedError()  # TODO

    def send_custom_watch():
        raise NotImplementedError()  # TODO


    @if_is_on
    def clear_all(self):
        self.send_control_command(ControlCommandType.ClearAll)

    @if_is_on
    def clear_auto_views(self):
        self.send_control_command(ControlCommandType.ClearAutoViews)

    @if_is_on
    def clear_watches(self):
        self.send_control_command(ControlCommandType.ClearWatches)

    @if_is_on
    def clear_log(self):
        self.send_control_command(ControlCommandType.ClearLog)

    @if_is_on
    def clear_process_flow(self):
        self.send_control_command(ControlCommandType.ClearProcessFlow)



def parse_connections(connection_str):
    """Helper utility generator; parses a connection string with
    protocol/options and yields ``Protocol`` instances.

    Combines the ConnectionsParser and OptionsParser classes from
    the Delphi implementation.

    Here's a regex that would match a full connection string; for parsing,
    we need to break it up to parse out the option list separately.
        ([a-z]+)   \(          # protocol name
            (                  # multiple options
                ([a-z]+) =     # option name =
                   # option value (escape with ")
                   ((?:"[^"]*(?:"")?[^"]*")|\w+)
                   # option seperator or end
                   (?:\s*(,\s*|(?=\))))
            )*
        \)
        \s*(,|$)               # protocol separator
    """
    re_connections = re.compile(r'([a-z]+)\((.*?)\)(?:,|$)')
    re_options = re.compile(r'([a-z]+)=((?:"[^"]*(?:"")?[^"]*")|\w+)\s*(?:,\s*|$)')
    def rsvopt(opt):
        """Resolve string to option."""


    connections = []
    while connection_str:
        m_connection = re_connections.search(connection_str)
        if not m_connection:
            raise InvalidConnectionsError('Invalid connection string: "%s"'%connection_str)
        protocol_name, option_str = m_connection.groups()
        connection_str = connection_str[m_connection.end():]
        connection = Protocols.get(protocol_name)

        options = {}
        while option_str:
            m_option = re_options.search(option_str)
            if not m_option:
                raise InvalidConnectionsError('Invalid option string: "%s"'%option_str)
            option_name, option_raw_value = m_option.groups()
            option_str = option_str[m_option.end():]

            # try to convert the value string to the right type
            option_value = None
            if option_raw_value.isdigit():
                option_value = int(option_raw_value)
            elif option_raw_value in ['yes', 'true']:
                option_value = True
            elif option_raw_value in ['0', 'no', 'false']:
                option_value = False
            elif option_raw_value.startswith('"') and\
                 option_raw_value.endswith('"') and\
                 len(option_raw_value)>1:
                option_value = option_raw_value[1:-1]
            else:
                # otherwise, this must be an enum identifer - but which one?
                for check in [Level, FileRotate]:
                    option_value = check.by_name(option_raw_value)
                    if option_value is None:
                        break
                if not option_value is None:
                    raise InvalidConnectionsError(option_raw_value)

            options[option_name] = option_value

        # finally, add the found connection to the list
        connection.options = options
        connections.append(connection)

    # Return what we have found; note that we have first parsed the whole
    # string - possible errors have already been caught. E.g. this function
    # will either succeed and return all connections, or fail fully (no
    # partial results). This effects the callers exception handling.
    for c in connections:
        yield c

def make_connection_string(connection_list):
    """Serialize a list of ``Protocol`` instances into a string (their
    options, to be exact. This is the opposite of ``parse_connections``.

    In Delphi, this is implemented via the ConnectionsBuilder class.
    """
    def fmtopt(option):
        if option is None:
            return "none"
        elif isinstance(option, bool):
            return option and 'true' or 'false'
        elif isinstance(option, type(Level.Debug)):  # EnumInstance
            return option.name(short=True).lower()
        elif isinstance(option, int):
            return '%s' % option
        else:  # elif isinstance(option, basestring)
            return '"%s"' % option
    return ",".join(["%s(%s)" % (connection.name,
        ",".join([
             "%s=%s" % (option, fmtopt(getattr(connection.options, option)))
             for option in connection.options
        ]))
        for connection in connection_list
    ])

class SmartInspect(object):
    """Main entry point; Manages a list of ``Session``s"""

    version = VERSION

    def __init__(self, appname):
        self.level = Level.Debug
        self.defaultlevel = Level.Message
        self.appname = appname
        self.hostname = socket.gethostname()
        self._enabled = False

        self._eventlock = threading.RLock()
        self._mainlock = threading.RLock()
        self._sessionlock = threading.RLock()

        self._sessions = {}
        self._connections = []

    def _set_connections(self, value):
        with self._mainlock:
            # disconnect first, and reset connection list
            self.disconnect()
            self._connections = []

            for connection in parse_connections(value):
                self._connections.append(connection)

            # if we're currently enabled,
            # then connect right away.
            if self.enabled:
                self.connect()
    def _get_connections(self):
        return make_connection_string(self._connections)
    connections = property( _get_connections, _set_connections)

    def load_connections(self):   # TODO
        """Read the connections string form a file."""
        raise NotImplementedError()

    def load_configuration(self, filename):
        """Load configuration from a file."""
        with self._mainlock:
            config = {}
            f = open(filename)
            with f:
                for line in f:
                    line = line.strip()
                    if line and not line[1] == ';':
                        key, value = line.split("=")
                        config[key.strip()] = value.strip()

            self.appname = config.get('appname', self.appname)
            self.level = Level.by_name(config.get('level', None), self.level)
            self.defaultlevel = Level.by_name(config.get('defaultlevel', None),
                                              self.defaultlevel)

            # applying connections is tougher; make sure that depending on the
            # value of "enabled" we set the new connections at the right point
            # in time, so that enabling will work with the new connections, but
            # disabling still uses the old ones.
            connections = configuration.get('connections', '')
            if 'enabled' in configuration:
                enabled = configuration['enabled']

                if enabled:
                    self.connections = connections
                    self.enable()
                else:
                    self.connections = connections
                    tryconnections(connections)
            else:
                self.connections = connections


    def connect(self):
        for connection in self._connections:
            connection.connect()

    def disconnect(self):
        for connection in self._connections:
            connection.disconnect()


    def add_session(self, name, store=False):
        result = Session(self, name)
        with self._sessionlock:
            if store:
                self._sessions[name] = result
                result.is_stored = True
        return result

    def _update_session(self, session, to, from_):
        with self._sessionlock:
            s = self._sessions[from_]
            if s == session:
                del self._sessions[from_]
            self._sessions[to] = session

    def get_session(self, name):
        with self._sessionlock:
            return self._sessions[name]

    def delete_session(session):
        """
        ``session`` can be a ``Session`` instance or the name of a stored
        session.
        """
        with self._sessionlock:
            if isinstance(session, basesstring):
                del self._sessions[name]
            else:
                for key, value in self._sessions.iteritems():
                    if value == session:
                        del self._sessions[key]
                        break

    def find_protocol(self, caption):
        """Find a protocol by it's ``caption`` option, or ``None`` if not
        found.

        Python port note: This method is protected in Delphi, but is very
        useful as a public functionality, for example in our tests where we
        need to check if a dispatch() call will work, or fail.
        """
        for connection in self._connections:
            if connection.options.caption == caption:
                return connection
        return None


    def dispatch(self, caption, action, state):
        with self._mainlock:
            protocol = self.find_protocol(caption)
            if not protocol:
                raise SmartInspectError(CAPTION_NOT_FOUND_MSG)

        command = ProtocolCommand(action, state)
        protocol.dispatch(command)

    def filter(self, packet):
        """Return False to allow the packet to pass."""
        # TODO: allow callback to user
        return False

    def now(self):
        # return datetime.datetime.utcfromtimestamp(time.time())
        return datetime.datetime.now()

    def process_packet(self, packet):
        with self._mainlock:
            for connection in self._connections:
                connection.write_packet(packet)

    def send_control_command(self, control_command):
        if not self.filter(control_command):
            self.process_packet(control_command)

    def send_log_entry(self, log_entry):
        log_entry.appname = self.appname
        log_entry.hostname = self.hostname
        if not self.filter(log_entry):
            self.process_packet(log_entry)

    def send_process_flow(self, process_flow):
        process_flow.hostname = self.hostname
        if not self.filter(process_flow):
            self.process_packet(process_flow)

    def send_watch(self, watch):
        if not self.filter(watch):
            self.process_packet(watch)

    def _set_enabled(self, value):
        value and [self.enable()] or [self.disable()]
    enabled = property(lambda s: s._enabled, _set_enabled)

    def disable(self):
        if self._enabled:
            self._enabled = False
            self.disconnect()

    def enable(self):
        if not self._enabled:
            self._enabled = True
            self.connect()