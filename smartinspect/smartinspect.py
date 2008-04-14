"""A SmartInspect Python Library.

Port of SmartInspect.pas (from SmartInspect Professional v2.3.3.7025)

NOTE: Many things in here have not yet been tested at all. This code is alpha
quality in a very real sense. You have been warned.

Compatibility Notes:

    * Identifers have been changed to conform with the Python style guide. In
      some instances it made sense to slightly modify implementations, say
      using a property instead of a simple get-method.

    * Due to the dynamic nature of Python the number of Log*, Watch* etc.
      methods could be drastically reduced. In particular, we are taking
      advantage of Python's optional keyword arguments, simple string
      formatting and loose-typing.

    * The events of the ``SmartInspect`` class (OnWatch, OnLogEntry, ...) do
      not exist. If needed, implementing such callbacks could be considered.

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
import sys
import threading
import StringIO


__all__ ('SmartInspect', 'Session',)



################################################################################
## Global constants.
################################################################################

VERSION = '2.3.3.7025'
TCP_CLIENT_BANNER = 'SmartInspect Python Library v' + VERSION;

DEFAULT_COLOR = False  # TODO
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
    filename = ""

class LoadConfigurationsError(SmartInspectError):
    filename = ""

class ProtocolError(SmartInspectError):
    """Error raised in Protocol-related code.

    References the ``Protocol`` instance directly, instead of storing it's name
    and options string, as in the Delphi implementation.
    """
    def __init__(message, protocol, *args, **kwargs):
        self.protocol = protocol
        super(ProtocolError, self).__init__(message, *args, **kwargs)

class InvalidConnectionsError(SmartInspectError): pass



################################################################################
## Enumerations.
################################################################################

class PacketType:
    """IDs as expected by SI console."""
    LogEntry = 4
    ControlCommand = 1
    Watch = 5
    ProcessFlow = 6

class LogEntryType:
    """IDs as expected by SI console.
    """
    """'Separator',        { ltSeparator }
    'EnterMethod',      { ltEnterMethod }
    'LeaveMethod',      { ltLeaveMethod }
    'ResetCallstack',   { ltResetCallstack }
    'Message',          { ltMessage }
    'Warning',          { ltWarning }
    'Error',            { ltError }
    'InternalError',    { ltInternalError }
    'Comment',          { ltComment }
    'VariableValue',    { ltVariableValue }
    'Checkpoint',       { ltCheckpoint }
    'Debug',            { ltDebug }
    'Verbose',          { ltVerbose }
    'Fatal',            { ltFatal }
    'Conditional',      { ltConditional }
    'Assert',           { ltAssert }
    'Text',             { ltText }
    'Binary',           { ltBinary }
    'Graphic',          { ltGraphic }
    'Source',           { ltSource }
    'Object',           { ltObject }
    'WebContent',       { ltWebContent }
    'System',           { ltSystem }
    'MemoryStatistic',  { ltMemoryStatistic }
    'DatabaseResult',   { ltDatabaseResult }
    'DatabaseStructure' { ltDatabaseStructure }"""
    Separator = 0
    EnterMethod = 1
    LeaveMethod = 2
    ResetCallback = 3
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

class ViewerId:
    """IDs as expected by SI console."""
    """
    'None',              { viNone }
    'Title',             { viTitle }
    'Data',              { viData }
    'List',              { viList }
    'ValueList',         { viValueList }
    'Inspector',         { viInspector }
    'Table',             { viTable }
    'Web',               { viWeb }
    'Binary',            { viBinary }
    'HtmlSource',        { viHtmlSource }
    'JavaScriptSource',  { viJavaScriptSource }
    'VbScriptSource',    { viVbScriptSource }
    'PerlSource',        { viPerlSource }
    'SqlSource',         { viSqlSource }
    'IniSource',         { viIniSource }
    'PythonSource',      { viPythonSource }
    'XmlSource',         { viXmlSource }
    'Bitmap',            { viBitmap }
    'Jpeg',              { viJpeg }
    'Icon',              { viIcon }
    'Metafile'           { viMetafile } """
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

class SourceId:
    Html = 1
    Javascript = 2
    VbScript = 3
    Perl = 4
    Sql = 5
    Ini = 6
    Python = 7
    Xml = 8

class GraphicId:
    Bitmap = 1
    Jpeg = 2
    Icon = 3
    Metafile = 4

class ControlCommandType:
    ClearLog = 1
    ClearWatches = 2
    ClearAutoViews = 3
    ClearAll = 4
    ClearProcessFlow = 5

class WatchType:
    Char = 1
    String = 2
    Integer = 3
    Float = 4
    Boolean = 5
    Address = 6
    Timestamp = 7
    Object = 8

class ProcessFlowType:
    EnterMethod = 1
    LeaveMethod = 2
    EnterThread = 3
    LeaveThread = 4
    EnterProcess = 5
    LeaveProcess = 6

class Level:
    """'Debug',     { lvDebug }
    'Verbose',   { lvVerbose }
    'Message',   { lvMessage }
    'Warning',   { lvWarning }
    'Error',     { lvError }
    'Fatal',     { lvFatal }
    'Unknown'    { lvControl, sic! }"""
    Debug = 1
    Verbose = 2
    Message = 3
    Warning = 4
    Error = 5
    Fatal = 6
    Control = 7

class FileRotate:
    """'None',      { frNone }
    'Hourly',    { frHourly }
    'Daily',     { frDaily }
    'Weekly',    { frWeekly }
    'Monthly'    { frMonthly }"""
    None_ = 1
    Hourly = 2
    Daily = 3
    Weekly = 4
    Monthly = 5



################################################################################
## Configuration/Option handling.
################################################################################

# TODO
#class ConnectionsBuilder(object): pass

# TODO
#class ConnectionsParser(object): pass

# TODO
#class OptionsParser(object): pass

# TODO
#class Configuration(object): pass



################################################################################
## Core classes (packet & packet types).
################################################################################

class Packet(object):
    """Base class for all packets."""
    def __init__(self):
        self.level = Level.Message
    def get_size(self):
        raise NotImplementedError()
    def get_packet_type(self):
        raise NotImplementedError()

class PacketQueue(object):
    def __init__(self, size=None):
        self._data = []
        self._size = size
    def _set_size(self, value):
        self._size = value
        self._resize()
    size = property(lambda s: self._size, _set_size)
    def _resize():
        while len(self._data) > self.size: self.pop()
    def clear(self):
        while self._data: self.pop()
    def push(self, packet):
        self._data.append(packet)
        self._resize()
    def pop():
        return self._data.pop(0)

class LogEntry(Packet):
    def __init__(self, log_entry_type, viewer_id):
        super(LogEntry, self).__init__()
        self._data = StringIO.StringIO()
        self.log_entry_type = log_entry_type
        self.viewer_id = viewer_id
        self.color = DEFAULT_COLOR
        # TODO
        self.thread_id = 0; # GetCurrentThreadId;
        self.process_id = 0; #GetCurrentProcessId;

    def get_size(self):
##            Result :=
##        SizeOf(TSiLogEntryHeader) +
##        Length(FSessionName) +
##        Length(FTitle) +
##        Length(FAppName) +
##        Length(FHostName);
##
##      if Assigned(FData) then
##      begin
##        Inc(Result, FData.Size);
##      end;
        pass

    def get_packet_type(self):
        return PacketType.LogEntry

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
        return self._data and self._data.size > 0

class ControlCommand(Packet):
    def __init__(self, control_command_type):
        super(ControlCommand, self).__init__()
        self.control_command_type = control_command_type
        self.level = PacketLevel.Control

    def get_size():
##        Result := SizeOf(TSiControlCommandHeader)
##        if Assigned(FData) then
##        begin
##        Inc(Result, FData.Size);
##        end;
        pass

    def get_packet_type(self):
        return PacketType.ControlCommand

    def _get_data(self):
        return self._data
    def _set_data(self, value):
        if value:
            self._data = copy(value)
        else:
            self._data.clear()
    data = property(_get_data, _set_data)

    @property
    def has_data(self):
        return self._data and self._data.size > 0

class Watch(Packet):
    def __init__(self, watch_type):
        super(Watch, self).__init__()
        self.watch_type = watch_type

class ProcessFlow(Packet):
    def __init__(self, process_flow_type):
        super(ProcessFlow, self).__init__()
        self.process_flow_type = process_flow_type
        self.thread_id = GetCurrentThreadId
        self.process_id = GetCurrentProcessId

    def get_size():
##        Result :=
##        SizeOf(TSiProcessFlowHeader) +
##        Length(FTitle) +
##        Length(FHostName);
        pass

    def get_packet_type(self):
        return PacketType.Watch



################################################################################
## Protocols and related classes.
################################################################################

class Formatter(object):
    """Formatters are responsible for formatting and writing a packet."""
    def format(self, packet, stream):
        self.compile(packet)
        self.write(stream)

class BinaryFormatter(Formatter):
    max_capacity = 10 * 1024 * 1024

    def __init__(self):
        self._stream = StringIO.StringIO()
        self._size = 0

    def write(self, stream):
        if self._size > 0:
##            LHeader.PacketSize := FSize;
##            LHeader.PacketType := CSiPacketTypeLookup[FPacket.PacketType];
##            AStream.Write(LHeader, SizeOf(LHeader));
##            FStream.Position := 0;
##            AStream.CopyFrom(FStream, FSize);
            pass

    def _reset_stream(self):
        if self._size > BinaryFormatter.max_capacity:
            # Reset the stream capacity if the previous packet
            # was very big. This ensures that the amount of memory
            # can shrink again after a big packet has been sent.
            self._stream.clear()
        else:
            # Only reset the position. This ensures a very good
            # performance since no reallocations are necessary.
            self._stream.position = 0

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

        size = self.stream.position
        return size + len(SiPacketHeader)

    def _compile_control_command(self):
        pass
##        var
##          LHeader: TSiControlCommandHeader;
##          LControlCommand: TSiControlCommand;
##        begin
##          LControlCommand := TSiControlCommand(FPacket);
##          LHeader.ControlCommandType := Ord(LControlCommand.ControlCommandType);
##
##          if LControlCommand.HasData then
##            LHeader.DataLength := LControlCommand.Data.Size
##          else
##            LHeader.DataLength := 0;
##
##          FStream.Write(LHeader, SizeOf(LHeader));
##
##          if LControlCommand.HasData then
##          begin
##            FStream.CopyFrom(LControlCommand.Data, 0);
##            LControlCommand.Data.Position := 0;
##          end;

    def _compile_log_entry(self):
        pass
##        var
##          LLogEntry: TSiLogEntry;
##          LHeader: TSiLogEntryHeader;
##          LTitle: UTF8String;
##          LHostName: UTF8String;
##          LSessionName: UTF8String;
##          LAppName: UTF8String;
##        begin
##          LLogEntry := TSiLogEntry(FPacket);
##          LTitle := UTF8Encode(LLogEntry.Title);
##          LHostName := UTF8Encode(LLogEntry.HostName);
##          LSessionName := UTF8Encode(LLogEntry.SessionName);
##          LAppName := UTF8Encode(LLogEntry.AppName);
##
##          LHeader.LogEntryType := CSiLogEntryTypeLookup[LLogEntry.LogEntryType];
##          LHeader.ViewerId := CSiViewerIdLookup[LLogEntry.ViewerId];
##          LHeader.AppNameLength := Length(LAppName);
##          LHeader.SessionNameLength := Length(LSessionName);
##          LHeader.TitleLength := Length(LTitle);
##          LHeader.HostNameLength := Length(LHostName);
##
##          if LLogEntry.HasData then
##            LHeader.DataLength := LLogEntry.Data.Size
##          else
##            LHeader.DataLength := 0;
##
##          LHeader.ThreadId := LLogEntry.ThreadId;
##          LHeader.ProcessId := LLogEntry.ProcessId;
##          LHeader.TimeStamp := LLogEntry.Timestamp;
##          LHeader.Color := LLogEntry.Color;
##
##          FStream.Write(LHeader, SizeOf(LHeader));
##          WriteString(LAppName, FStream);
##          WriteString(LSessionName, FStream);
##          WriteString(LTitle, FStream);
##          WriteString(LHostName, FStream);
##
##          if LLogEntry.HasData then
##          begin
##            FStream.CopyFrom(LLogEntry.Data, 0);
##            LLogEntry.Data.Position := 0;
##          end;

    def _compile_process_flow(self):
        pass
##        var
##          LProcessFlow: TSiProcessFlow;
##          LHeader: TSiProcessFlowHeader;
##          LTitle: UTF8String;
##          LHostName: UTF8String;
##        begin
##          LProcessFlow := TSiProcessFlow(FPacket);
##          LTitle := UTF8Encode(LProcessFlow.Title);
##          LHostName := UTF8Encode(LProcessFlow.HostName);
##
##          LHeader.ProcessFlowType := Ord(LProcessFlow.ProcessFlowType);
##          LHeader.TitleLength := Length(LTitle);
##          LHeader.HostNameLength := Length(LHostName);
##          LHeader.ThreadId := LProcessFlow.ThreadId;
##          LHeader.ProcessId := LProcessFlow.ProcessId;
##          LHeader.Timestamp := LProcessFlow.Timestamp;
##
##          FStream.Write(LHeader, SizeOf(LHeader));
##          WriteString(LTitle, FStream);
##          WriteString(LHostName, FStream);

    def _compile_watch(self):
        pass
##        var
##          LWatch: TSiWatch;
##          LHeader: TSiWatchHeader;
##          LName: UTF8String;
##          LValue: UTF8String;
##        begin
##          LWatch := TSiWatch(FPacket);
##          LName := UTF8Encode(LWatch.Name);
##          LValue := UTF8Encode(LWatch.Value);
##
##          LHeader.NameLength := Length(LName);
##          LHeader.ValueLength := Length(LValue);
##          LHeader.WatchType := Ord(LWatch.WatchType);
##          LHeader.Timestamp := LWatch.Timestamp;
##
##          FStream.Write(LHeader, SizeOf(LHeader));
##          WriteString(LName, FStream);
##          WriteString(LValue, FStream);

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

# TODO
# class FileRotater(object): pass

# TODO
#class FileStorage(object):
#    """Responsible for tracking and deleting old backup files."""
#    pass

class ProtocolCommand(object):
    def __init__(self, action, state):
        self.action = action
        self.state = state

class ProtocolOptions(object):
    """Manages a set of options for a protocol instance.

    This replaces the BuildOptions/LoadOptions methods on ``Protocol``
    classes in the Delphi implementation.
    """

    def __init__(self, protocol):
        self._options = {}
        self.protocol = protocol

    def __setattr__(self, key, value):
        with self._protocol._lock:
            if self._protocol.connected:
                raise SmartInspectError(SiProtocolConnectedError)

            _validate_option(key)
            self._options[key] = value

    def __getattr__(self, key):
        with self._protocol._lock:
            _validate_option(key)
            return self_options.get(key, None)

    def _validate_option(self, option):
        if not option in self.protocol.valid_options.keys():
            raise SmartInspectError(u'Option "%s" not available for '+
                u'protocol "%s"' % [option, self.protocol.name]);

    def reset(self):
        """Reset to default values"""
        for option, default_value in self.protocol.valid_options.items():
            setattr(self, option, default_value)

class Protocol(object):
    """A protocol is responsible for the transport of packets."""

    valid_options = {'level': Level.Debug,
                     'backlog': 0,
                     'flushon': Level.Error,
                     'reconnect':False,
                     'keepopen': True, \
                     'caption': None} # TODO: default this to Protocol.name

    def __init__(self):
        self._lock = threading.RLock()
        self.connected = False
        self.options = ProtocolOptions(self)
        """
          # TODO: options callback??
          if FBacklog > 0 then
            FKeepOpen := GetBooleanOption('keepopen', SiProtocolKeepOpen)
          else
            FKeepOpen := True;
          FQueue.Backlog := FBacklog;
          """
        #self.queue := TSiPacketQueue.Create;
        #self.queue.OnDelete := DeletePacket;

    def _internal_reconnect(self):
        self._internal_connect()

    def _internal_dispatch(self, command):
        # empty by default
        pass

    def connect(self):
        with self._lock:
            if not self.connected and self.options.keep_open:
                try:
                    self._internal_connect()
                    connected = True
                except Exception, e:
                    self.reset()

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
        self._conncted = False
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
            if not self.options.keep_open:
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
                    not self.options.keep_open:
                try:
                    skip = False

                    if self.options.backlog > 0:
                        if packet.level >= self.options.flush_on and \
                            packet.level <> PacketLevel.Control:
                                p = self.queue.pop()
                                while p:
                                    try:
                                        self.forward_packet(p, False)
                                    finally:
                                        p.release()
                                    p = self.queue.pop()
                        else:
                            self.queue.push(packet)
                            skip = True

                    if not skip:
                        self.forward_packet(packet, not self.options.keep_open)
                except Exception, e:
                    self.reset()
                    raise ProtocolError(str(e), self)

class MemoryProtocol(Protocol):
    name = "mem"

    valid_options = {
        'astext': False,
        'maxsize': 2048,
        'pattern': DEFAULT_TEXT_PATTERN,
        'indent': False}

    def __init__(self):
        super(MemoryProtocol, self).__init__(self)

    def _initialize_formatter(self):
        # TODO: call this on option change?
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

        if command is Stream:
            s = command.state

            if self.options.astext:
                s.write('\xef\xbb\xbf')  # bom header
            else:
                s.write(SiMagicLogString)

            packet = self.queue.pop()
            while packet:
                self.formatter.format(packet, s)
                packet = queue.pop()

    def _internal_write_packet(self, packet):
        self.queue.push(packet)

# TODO
#class FileProtocol(Protocol):
#    pass

# TODO
#class TextProtocol(Protocol):
#    pass

class TcpProtocol(Protocol):
    name = "tcp"

    valid_options = {'host': '127.0.0.1',
                     'port': 4228,
                     'timeout': 30000}

    def __init__(self):
        self.formatter = BinaryFormatter()

    def _internal_connect(self):
        self.client = TcpClient(self.options.host, self.options.port)
        self.client.connect(self.options.timeout)
        #FStream := TSiTcpClientStream.Create(FTcpClient);
        #FStream.ReadLn;
        #FStream.WriteLn(SiTcpClientBanner);
        #FBuffer := TSiBufferedStream.Create(FStream, $2000);

    def _internal_write_packet(packet):
##        FFormatter.Format(APacket, FBuffer);
##        FBuffer.Flush;
##
##        // Read (and wait for) the server answer.
##        if FBuffer.Read(LAnswer, SizeOf(LAnswer)) <> SizeOf(LAnswer) then
##        begin
##        // We couldn't read the entire answer from the server, but the
##        // Read method didn't raise an exception. This means that the
##        // socket connection has been normally closed by the server,
##        // but this shouldn't occur while trying to read the answer!
##        raise ESmartInspectError.Create(SiSocketClosedError);
        pass

    def _internal_disconnect(self):
        del self.client

class Protocols(object):
    """Globally manage a list of available protocols.

    Thread-safe.

    Replaces the ProtocolFactory class of the Delphi implementation.
    """
    _table = {}
    _lock = threading.Lock()

    @classmethod
    def get(cls, name, options):
        with cls._lock:
            result = cls._table.get(name, False)()
            if not result:
                raise SmartInspectError(u'Protocol "%s" not found'%name)
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
    def wrapper(self, *args, **kwargs):
        return func(self, *args, **kwargs)
    return wrapper

def if_is_on(func):
    def wrapper(self, *args, **kwargs):
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

    def is_on(level=None):
        return self.active and self.parent.enabled and (
                    level >= self.parent.level or not level)




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

    def send_process_fow(self, level, title, process_flow_type):
        process_flow = ProcessFlow(process_flow_type)
        process_flow.timestamp = self.parent.now()
        process_flow.level = level
        process_flow.title = title
        self.parent.send_process_flow(self.process_flow)

    def send_watch(self, level, name, value, watch_type):
        watch = Watch(watch_type)
        watch.timestamp = self.parent.now()
        watch.level = level
        watch.title = title
        watch.value = value
        self.parent.send_watch(self.process_flow)

    def send_control_command(self, control_command_type, data):
        control_command = ControlCommand(control_command_type)
        control_command.level = Level.Control
        control_command.data = data
        self.parent.send_control_command(control_command)

    def send_context():
        # TODO: just send_log_entry with a viewer instance as the data part
        raise NotImplementedError()



    @default_level_to_parent
    @if_is_on
    def log_value(self, name, value, level=None, *args, **kwargs):
        title = "%s = %s" % (name, value)
        # of some values require custom formatting in the future, do this here
        self.log(level, title,
                 entry_type=LogEntryType.VariableValue,
                 *args, **kwargs)

    @default_level_to_parent
    @if_is_on
    def log(self, title, level=None, color=None,
            entry_type=LogEntryType.Message):
        self.send_log_entry(level, title, entry_type, ViewerId.Title,
                            color=color)

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

    @default_level_to_parent
    @if_is_on
    def log_separator(self, level=None):
        self.send_log_entry(level, '', LogLevelType.Separator)

    def log_assert(self, condition, title):
        if self.is_on(LogLevel.Error):
            if not condition:
                self.send_log_entry(LogLevel.Error, title, LogEntryType.Assert,
                                    ViewerId.Title)

    def log_internal_error(self, title):
        if self.is_on(LogLevel.Error):
            self.send_log_entry(LogLevel.Error, title,
                                LogEntryType.InternalError, ViewerId.Title)




    @default_level_to_parent
    def reset_callstack(self, level=None):
        self.send_log_entry(level, '', LogEntryType.ResetCallstack)

    @default_level_to_parent
    def enter_method(self, name, level=None, instance=None):
        if self.is_on(level):
            if instance:
                name = "%s.%s" %(type(instance).__name__, name)

            # send two packets, one log entry and one process flow entry
            self.send_log_entry(level, name, LogEntryType.EnterMethod,
                                ViewerId.Title);
            self.send_process_flow(level, name, ProcessFlow.EnterMethod)

    @default_level_to_parent
    def leave_method(self, name, level=None, instance=None):
        if self.is_on(level):
            if instance:
                name = "%s.%s" %(type(instance).__name__, name)

            # send two packets, one log entry and one process flow entry
            self.send_log_entry(level, name, LogEntryType.EnterMethod,
                                ViewerId.Title);
            self.send_process_flow(level, name, ProcessFlow.LeaveMethod)


    @default_level_to_parent
    def enter_thread(self, name, level=None):
          if self.is_on(level):
              self.send_process_flow(level, name, ProcessFlow.EnterThread)

    @default_level_to_parent
    def leave_thread(self, name, level=None):
          if self.is_on(level):
              self.send_process_flow(level, name, ProcessFlow.LeaveThread)

    @default_level_to_parent
    def enter_process(self, name=None, level=None):
          if self.is_on(level):
              self.send_process_flow(level, name or self.parent.appname,
                                     ProcessFlow.EnterProcess)
              self.send_process_flow(level, 'Main Thread', ProcessFlow.EnterThread)

    @default_level_to_parent
    def leave_process(self, name=None, level=None):
          if self.is_on(level):
              self.send_process_flow(level, name or self.parent.appname,
                                     ProcessFlow.LeaveProcess)
              self.send_process_flow(level, 'Main Thread', ProcessFlow.LeaveThread)




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

    def log_last_error(self, name):
        if self.is_on(LogLevel.Error):
            self.log_exception(sys.last_value)





    @if_is_on
    def clear_all(self):
        self.send_control_command(ControlCommand.ClearAll)

    @if_is_on
    def clear_auto_views(self):
        self.send_control_command(ControlCommand.ClearAutoViews)

    @if_is_on
    def clear_watches(self):
        self.send_control_command(ControlCommand.ClearWatches)

    @if_is_on
    def clear_log(self):
        self.send_control_command(ControlCommand.ClearLog)

    @if_is_on
    def clear_process_flow(self):
        self.send_control_command(ControlCommand.ClearProcessFlow)




    @default_level_to_parent
    @if_is_on
    def watch_boolean(self, name, value, level=None):
        self.send_watch(level, name, value and 'True' or 'False',
                        WatchType.Boolean)

    @default_level_to_parent
    @if_is_on
    def watch_boolean(self, name, value, level=None):
        self.send_watch(level, name, value, WatchType.Char)




    @default_level_to_parent
    def add_checkpoint(self, level=None):
        with self._checkpointlock:
            self._checkpoint_counter += 1
            counter = self._checkpoint_counter

        if self.is_on(level):
            title = 'Checkpoint #%d' % counter
            self.send_log_entry(level, title, LogEntryType.Checkpoint,
                                ViewerId.Title)

    def reset_checkpoint(self):
        with self._checkpointlock:
            self._checkpoint_counter = 0




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


class SmartInspect(object):
    """Main entry point; Manages a list of ``Session``s"""

    version = VERSION

    def __init__(self, appname):
        self.level = Level.Debug
        self.default_level = Level.Message

        self._eventlock = threading.RLock()
        self._mainlock = threading.RLock()
        self._sessionlock = threading.RLock()

        self._sessions = {}
        self._connections = []

        self.appname = appname
        # TODO
        self.hostname = ""
        self.enabled = False

    def connect(self):
        for connection in self._connections:
            try:
                connection.connect()
            except Exception, e:
                self._error(e)

    def disconnect(self):
        for connection in self._connections:
            try:
                connection.disconnect()
            except Exception, e:
                self._error(e)


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


    def clear_connections(self):
        self.connections = []

    def load_connections(self):
        raise NotImplementedError()    # TODO

    def read_connections(self):
        raise NotImplementedError()    # TODO

    def apply_connections(self):
        raise NotImplementedError()    # TODO

    def try_connections(self):
        raise NotImplementedError()    # TODO

    def remove_connections(self):
        raise NotImplementedError()    # TODO

    def load_configuration(self):
        raise NotImplementedError()    # TODO

    def apply_configuration(self):
        raise NotImplementedError()    # TODO


    def dispatch(self, caption, action, state):
        with self._mainlock:
            # find the protocol by the caption queried
            protocol = None
            for connection in self._connections:
                if connection.caption == caption:
                    protocol = connection
                    break
            if not protocol:
                raise SmartInspectError(SiCaptionNotFoundError)

        command = ProtocolCommand(action, state)
        protocol.dispatch(command)

    def filter(self, packet):
        # TODO: allow callback to user
        return True

    def now(self):
        # TODO
        return 0

    def process_packet(self, packet):
        with self._mainlock:
            for connection in self._connections:
                try:
                    connection.write_packet(packet)
                except Exception, e:
                    self._error(e)

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


    def disable(self):
        if self._enabled:
            self.enabled = False
            self.disconnect()

    def enable(self):
        if not self._enabled:
            self._enabled = True
            self.connect()



################################################################################
## Module startup.
################################################################################

Protocols.register('mem', MemoryProtocol)
Protocols.register('tcp', TcpProtocol)
# Not yet supported
#Protocols.register('file', FileProtocol)
#Protocols.register('text', TextProtocol)