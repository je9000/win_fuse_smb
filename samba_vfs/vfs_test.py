import sys

root = {}
root['.'] = root;
root['..'] = root;
root['testfile1'] = "file 1 data";
root['testfile2'] = "file 2 data";

fd = 0
fdmap = {}

def connect(service, user):
    print >> sys.stderr, "Someone connected! Service = %s, User = %s" % ( service, user )
    return 0

def getdir(a):
    global root
    if a != '/' and a != '.': return -1
    return root.keys()

def fstat(fd):
    global fdmap
    print >> sys.stderr, "Being asked fstat for %i" % fd
    if fdmap.has_key(fd):
        a = fdmap[fd]
        if type(root[a]) == type(''):
            return { "st_mode": 0755, "st_ino": id(root[a]) }
        return { "st_mode": 0040000 | 0755, "st_ino": id(root[a]) }
    return 0

def getattr(a):
    global root
    print >> sys.stderr, "Got a call to getattr for %s" % a
    if a == '/': a = '.'
    if root.has_key(a):
        if type(root[a]) == type(''):
            return { "st_mode": 0755, "st_ino": id(root[a]) }
        return { "st_mode": 0040000 | 0755, "st_ino": id(root[a]) }
    return -1

def close(a):
    global fdmap
    print >> sys.stderr, "Got close for fd %i" % a
    if fdmap.has_key(a):
        del fdmap[a]
        return 0
    return -1

def open(a, b, c):
    global fd
    global fdmap
    print >> sys.stderr, "Got a call to open for %s" % a
    if root.has_key(a):
        fd = fd + 1
        fdmap[fd] = a
        return fd
    return -1

def create(a, b):
    global root
    print >> sys.stderr, "Got a call to create for %s" % a
    if root.has_key(a): return -1
    root[a] = "";
    return 0

def unlink(a):
    global root
    print >> sys.stderr, "Got a call to unlink for %s" % a
    if not root.has_key(a): return -1
    del root[a];
    return 0

