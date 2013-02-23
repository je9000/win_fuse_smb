import sys
import os

root = {}
root['.'] = root;
root['..'] = root;
root['testfile1'] = bytearray("file 1 data");
root['testfile2'] = bytearray("file 2 data");
root['testdir'] = { "testdirfile1" : bytearray("test dir file 1") }

fd = 0
fdmap = {}

def find_node_or_parent(path, parent):
    global root
    currently_at = start_at = root
    split_path = path.split("/")
    if parent: split_path = split_path[:-1]
    try:
        for node in split_path:
            if node == "" or node == ".": continue
            if type(currently_at) is not dict: raise Exception
            currently_at = currently_at[node]
        return currently_at
    except Exception:
        return None
    
def find_parent(path):
    return find_node_or_parent(path, 1)

def find_node(path):
    return find_node_or_parent(path, 0)

def basename(path):
    split_path = path.split("/")
    return split_path[-1]

def connect(service, user):
    print >> sys.stderr, "Someone connected! Service = %s, User = %s" % ( service, user )
    return 0

def getdir(a):
    found = find_node(a)
    if not found or type(found) is not dict: return -1
    return found.keys()

def fstat(fd):
    global fdmap
    print >> sys.stderr, "Being asked fstat for %i" % fd
    if fdmap.has_key(fd):
        return getattr(fdmap[fd]['name'])
    return -1

def getattr(a):
    print >> sys.stderr, "Got a call to getattr for ->%s<-" % a
    node = find_node(a)
    if node is not None:
        if type(node) is bytearray:
            return { "st_mode": 0777, "st_ino": id(node), "st_size": len(node) }
        return { "st_mode": 0040000 | 0777, "st_ino": id(node) }
    return -1

def close(a):
    global fdmap
    print >> sys.stderr, "Got close for fd %i" % a
    if fdmap.has_key(a):
        del fdmap[a]
        return 0
    return -1

def open(cwd, a, b, c):
    global fd
    global fdmap
    print >> sys.stderr, "Got a call to open for %s in cwd %s" % (a,cwd)
    a = cwd + '/' + a
    # existing
    node = find_node(a)
    if node is not None:
        fd = fd + 1
        fdmap[fd] = { 'name': a, 'off': 0 }
        print >> sys.stderr, "Opened %s at fd %i" % (a,fd)
        return fd
    # new
    parent = find_parent(a)
    if parent is not None:
        fname = basename(a)
        parent[fname] = bytearray()
        fd = fd + 1
        fdmap[fd] = { 'name': a, 'off': 0 }
        print >> sys.stderr, "Created %s at fd %i" % (a,fd)
        return fd
    return -1

def unlink(a):
    global root
    print >> sys.stderr, "Got a call to unlink for %s" % a
    node = find_node(a)
    if node is None: return -1
    del find_parent(a)[basename(a)];
    return 0

def read(fd, size):
    global fdmap
    print >> sys.stderr, "Got a call to read for fd %i size %i" % ( fd, size )
    try:
        fdinfo = fdmap[fd]
        node = find_node(fdinfo['name'])
        r = node[fdinfo['off']:fdinfo['off'] + size]
        fdinfo['off'] = fdinfo['off'] + size
        if fdinfo['off'] > len(node): fdinfo['off'] = len(node)
        return r

    except Exception as e:
        print >> sys.stderr, "Read returning -1 because of ", e
        return -1

def write(fd, data):
    global fdmap
    print >> sys.stderr, "Got a call to write for fd %i size %i" % ( fd, len(data) )
    try:
        fdinfo = fdmap[fd]
        node = find_node(fdinfo['name'])
        node[fdinfo['off'] : fdinfo['off'] + len(data)] = data
        fdinfo['off'] = fdinfo['off'] + len(data)
        return len(data)

    except Exception as e:
        print >> sys.stderr, "Write returning -1 because of ", e
        return -1

def lseek(fd, where, whence):
    global fdmap
    print >> sys.stderr, "Got a call to lseek for fd %i" % fd
    try:
        fdinfo = fdmap[fd]
        node = find_node(fdinfo['name'])
        if whence == os.SEEK_SET:
            fdinfo['off'] = where
        elif whence == os.SEEK_CUR:
            fdinfo['off'] = fdinfo['off'] + where
        elif whence == os.SEEK_END:
            fdinfo['off'] = len(node) + where
        else:
            print >> sys.stderr, "What's seek %i" % whence
            raise Exception
        return fdinfo['off']  
        
    except Exception:
        print >> sys.stderr, "lseek returning -1"
        return -1

