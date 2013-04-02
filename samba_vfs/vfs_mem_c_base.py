import sys
import os
import Pyro4

def connect(service, user, arg):
    p = Pyro4.Proxy("PYRO:mem_fs@localhost:5559")

def disconnect():

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

def rename(src, dst):

