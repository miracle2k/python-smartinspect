import sys

def mem2stdout(si):
    if si.find_protocol('mem'):
        import StringIO
        s = StringIO.StringIO()
        si.dispatch('mem', 0, s)

        if sys.platform == "win32":
            import os, msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        sys.stdout.write(s.getvalue())