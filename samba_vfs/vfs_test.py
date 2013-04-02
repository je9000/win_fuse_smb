import sys
import os

root = {}
root['.'] = root;
root['..'] = root;
root['testfile1'] = bytearray("file 1 data");
root['testfile2'] = bytearray("file 2 data");
root['testdir'] = { "testdirfile1" : bytearray("test dir file 1") }

#vfs_errno = 0

lastfd = 0
fdmap = {}

def alloc_fd():
    global lastfd
    global fdmap
    newfd = lastfd + 1
    if newfd > sys.maxint: newfd = 1
    if fdmap.has_key(newfd):
        newfd += 1
        if newfd > sys.maxint:
            newfd = 1
        if newfd == lastfd:
            raise Exception
    lastfd = newfd
    return newfd

def new_dir(parent):
    t = {}
    t['.'] = t
    t['..'] = parent
    return t

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

def connect(service, user, arg):
    print >> sys.stderr, "Someone connected! Service = %s, User = %s, Pid = %i, initobj = %s" \
        % ( service, user, os.getpid(), arg )
    return 0

def disconnect():
    print >> sys.stderr, "Disconnecting from pid %i!" % os.getpid()

def getdir(path):
    found = find_node(path)
    if not found or type(found) is not dict: return -1
    return found.keys()

def fstat(fd):
    global fdmap
    print >> sys.stderr, "Being asked fstat for %i" % fd
    if fdmap.has_key(fd):
        return stat(fdmap[fd]['name'], 0)
    return -1

def stat(path, do_lstat):
    print >> sys.stderr, "Got a call to stat for %s (lstat is %i)" % ( path, do_lstat )
    node = find_node(path)
    if node is not None:
        if type(node) is bytearray:
            return { "st_mode": 0777, "st_ino": id(node), "st_size": len(node) }
        return { "st_mode": 0040000 | 0777, "st_ino": id(node) }
    return -1

def close(path):
    global fdmap
    print >> sys.stderr, "Got close for fd %i" % path
    if fdmap.has_key(path):
        del fdmap[path]
        return 0
    return -1

def open(path, flags, mode):
    global fdmap
    print >> sys.stderr, "Got a call to open for %s" % path
    # existing
    node = find_node(path)
    if node is not None:
        fd = alloc_fd()
        fdmap[fd] = { 'name': path, 'off': 0 }
        print >> sys.stderr, "Opened %s at fd %i" % (path,fd)
        return fd
    # new
    parent = find_parent(path)
    if parent is not None:
        fname = basename(path)
        parent[fname] = bytearray()
        fd = alloc_fd()
        fdmap[fd] = { 'name': path, 'off': 0 }
        print >> sys.stderr, "Created %s at fd %i" % (path,fd)
        return fd
    return -1

def unlink(path):
    print >> sys.stderr, "Got a call to unlink for %s" % a
    if find_node(path) is None: return -1
    del find_parent(path)[basename(path)];
    return 0

def read(fd, size):
    global fdmap
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
    #print >> sys.stderr, "Got a call to write for fd %i size %i" % ( fd, len(data) )
    try:
        fdinfo = fdmap[fd]
        node = find_node(fdinfo['name'])
        node[fdinfo['off'] : fdinfo['off'] + len(data)] = data
        fdinfo['off'] = fdinfo['off'] + len(data)
        return len(data)

    except Exception as e:
        print >> sys.stderr, "Write returning -1 because of ", e
        return -1

def pwrite(fd, data, offset):
    global fdmap
    #print >> sys.stderr, "Got a call to write for fd %i size %i" % ( fd, len(data) )
    try:
        fdinfo = fdmap[fd]
        node = find_node(fdinfo['name'])
        node[offset : offset + len(data)] = data
        return len(data)

    except Exception as e:
        print >> sys.stderr, "Write returning -1 because of ", e
        return -1


def lseek(fd, where, whence):
    global fdmap
    #print >> sys.stderr, "Got a call to lseek for fd %i" % fd
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

def diskfree(path):
    return { "size": 1024*1024*1024*10, "used": 2048 }

def mkdir(path, mode):
    print >> sys.stderr, "Got a call to mkdir for %s" % path
    # existing
    if find_node(path) is not None:
        print >> sys.stderr, "mkdir path is not None"
        return -1
    # new
    parent = find_parent(path)
    if parent is not None:
        parent[basename(path)] = new_dir(parent)
        print >> sys.stderr, "Created directory %s" % path
        return 0
    print >> sys.stderr, "mkdir parent is None"
    return -1


def unlink(path):
    print >> sys.stderr, "Got a call to unlink for %s" % path
    try:
        parent = find_parent(path)
        del parent[basename(path)]
        return 0

    except Exception as e:
        return -1
