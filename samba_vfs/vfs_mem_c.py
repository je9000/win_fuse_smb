import sys
import os
import Pyro4

def connect(service, user, arg):
    global p
    p = Pyro4.Proxy("PYRO:mem_fs@localhost:5559")
    print >> sys.stderr, "Someone connected! Service = %s, User = %s, Pid = %i, initobj = %s" \
        % ( service, user, os.getpid(), arg )
    return p.connect(service, user, arg)

def disconnect():
    global p
    print >> sys.stderr, "Disconnecting from pid %i!" % os.getpid()
    return p.disconnect()

def getdir(path):
    global p
    return p.getdir(path)

def fstat(fd):
    global p
    return p.fstat(fd)

def stat(path, do_lstat):
    global p
    return p.stat(path, do_lstat)

def close(path):
    global p
    return p.close(path)

def open(path, flags, mode):
    global p
    return p.open(path, flags, mode)

def unlink(path):
    global p
    return p.unlink(path)

def read(fd, size):
    global p
    return p.read(fd, size)

def write(fd, data):
    global p
    return p.write(fd, data)

def pwrite(fd, data, offset):
    global p
    return p.pwrite(fd, data, offset)

def lseek(fd, where, whence):
    global p
    return p.lseek(fd, where, whence)

def diskfree(path):
    global p
    return p.diskfree(path)

def mkdir(path, mode):
    global p
    return p.mkdir(path, mode)

def unlink(path):
    global p
    return p.unlink(path)

