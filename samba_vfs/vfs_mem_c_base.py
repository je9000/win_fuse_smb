import sys
import os
import Pyro4

def connect(service, user, arg):
    p = Pyro4.Proxy("PYRO:mem_fs@localhost:5559")
    print >> sys.stderr, "Someone connected! Service = %s, User = %s, Pid = %i, initobj = %s" \
        % ( service, user, os.getpid(), arg )
    return 0

def disconnect():
    print >> sys.stderr, "Disconnecting from pid %i!" % os.getpid()

def getdir(path):

def fstat(fd):

def stat(path, do_lstat):

def close(path):

def open(path, flags, mode):

def unlink(path):

def read(fd, size):

def write(fd, data):

def pwrite(fd, data, offset):

def lseek(fd, where, whence):

def diskfree(path):

def mkdir(path, mode):

def unlink(path):

