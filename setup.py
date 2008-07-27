import os
from distutils.core import setup

def find_packages(root):
    # so we don't depend on setuptools; from the Storm ORM setup.py
    packages = []
    for directory, subdirectories, files in os.walk(root):
        if '__init__.py' in files:
            packages.append(directory.replace(os.sep, '.'))
    return packages

setup(
    name = 'python-smartinspect',
    version = '0.1',
    description = 'A SmartInspect client library for Python ('
        'gurock.com/products/smartinspect/).',
    author = 'Michael Elsdoerfer',
    author_email = 'michael@elsdoerfer.info',
    license = 'BSD',
    url = 'http://launchpad.net/python-smartinspect',
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Topic :: System :: Logging',
        'Topic :: Software Development :: Libraries',
        ],
    packages = find_packages('smartinspect'),
)
