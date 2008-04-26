"""
Tests that do various complete logging runs like they might happen in a real
application, and then check the output.

There's a partial attempt at testing the TCP protocol using a dummy server
in old SVN revisions, but this proved really complicated without implementing
the protocol server side, so we're skipping that for now.
"""
from __future__ import with_statement

import os
import subprocess
import SocketServer, socket
import StringIO
import threading

def test_examples(create_ref_data=False):
    """Run and test the example scripts in the subdirectory.

    If ``create_ref_data`` is ``True``, instead of testing the output of each
    test is stored in the appropriate .ref-file, replacing any existing. Use it
    to generate new reference data to test against.
    """
    tests_failed = 0

    basedir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    examplesdir = os.path.join(basedir, 'examples')
    for test_filename in os.listdir(examplesdir):
        test_filepath = os.path.join(examplesdir, test_filename)
        if not test_filename.endswith('.py') or os.path.isdir(test_filepath) or\
            test_filename.startswith('__'): continue

        # run each script in different variants
        for oname, option in [
                ('mem', "mem()"),
        ]:
            # run the test in the current variant
            p = subprocess.Popen([test_filepath, option], shell=True,
                                 stdout=subprocess.PIPE)
            test_output = p.communicate()[0]

            # path to the file containing the data to test against
            reference_filepath = \
                os.path.splitext(test_filepath)[0] + ('.%s.ref'%oname)

            # store the data in a reference file?
            if create_ref_data:
                reference_file = open(reference_filepath, 'wb')   # binary!!!
                with reference_file:
                    reference_file.write(test_output)

            # otherwise, compare test result with reference data
            else:
                if not os.path.exists(reference_filepath):
                    print "Skipping test %s/%s - reference file is missing: %s" %\
                        (test_filename, oname,
                         os.path.basename(reference_filepath))
                    continue

                reference_file = open(reference_filepath, 'rb')   # binary!!!
                reference_data = reference_file.read()

                # as we don't speak the protocol we can only compare the
                # length of the two data sets, which should match (the data
                # that varies, e.g. dates) will always have the same length
                # at least.
                if len(reference_data) != len(test_output):
                    tests_failed += 1
                    print 'Test %s/%s failed - does not match reference data!' %\
                        (test_filename, oname)

    if not create_ref_data:
        # summarize result
        print ""
        if tests_failed:
            print "RESULT: %d tests FAILED" % tests_failed
        else:
            print "RESULT: all tests OK"

        # cause py.test to fail
        assert tests_failed == 0

if __name__ == '__main__':
    test_examples(create_ref_data=True)