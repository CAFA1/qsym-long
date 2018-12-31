#!/usr/bin/env python2
import os
import subprocess
import multiprocessing as mp
try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

from distutils.core import setup
from distutils.command.build import build as DistutilsBuild

def build_pintool():
    if subprocess.call(["make", "-C", "qsym/pintool", "-j", str(mp.cpu_count())]) != 0:
        raise ValueError("Unable to build pintool")
    my_env = os.environ.copy()
    my_env["TARGET"] = "ia32"
    if subprocess.call(["make", "-C", "qsym/pintool", "-j", str(mp.cpu_count())], env=my_env) != 0:
        raise ValueError("Unable to build pintool")
    if int(open("/proc/sys/kernel/yama/ptrace_scope").read()) != 0:
        raise ValueError("Please disable yama/ptrace_scope:\n" \
                       + "echo 0 > /proc/sys/kernel/yama/ptrace_scope")

build_pintool()
