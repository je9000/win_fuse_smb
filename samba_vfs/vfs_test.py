import sys

root = {}

root['.'] = root;
root['..'] = root;
root['testfile1'] = "file 1 data";
root['testfile2'] = "file 2 data";

def connect(service, user):
    print >> sys.stderr, "Someone connected! Service = %s, User = %s" % ( service, user )
    return 0

def getdir(a):
    if a != '/' and a != '.': return -1
    return root.keys()

def getattr(a):
    print >> sys.stderr, "Got a call to getattr for %s" % a
    if a == '/': a = '.'
    if root.has_key(a):
        if type(root[a]) == type(''):
            print >> sys.stderr, "new id is %i" % id(root[a])
            return { "st_mode": 0755, "st_ino": id(root[a]) }
        print >> sys.stderr, "new id is %i for dir" % id(root[a])
        return { "st_mode": 0040000 | 0755, "st_ino": id(root[a]) }
    return -1

def open(a, b):
    print >> sys.stderr, "Got a call to open for %s" % a
    if root.has_key(a): return 0
    return -1

def create(a, b):
    print >> sys.stderr, "Got a call to create for %s" % a
    if root.has_key(a): return -1
    root[a] = "";
    return 0

def unlink(a):
    print >> sys.stderr, "Got a call to unlink for %s" % a
    if not root.has_key(a): return -1
    del root[a];
    return 0

