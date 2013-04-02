import sys
import os
import Pyro4

class mem_fs:
    root = {}
    root['.'] = root;
    root['..'] = root;
    root['testfile1'] = bytearray("file 1 data");
    root['testfile2'] = bytearray("file 2 data");
    root['testdir'] = { "testdirfile1" : bytearray("test dir file 1") }

    vfs_errno = 0

    lastfd = 0
    fdmap = {}

    def errno(self):
        return vfs_errno

    def alloc_fd(self):
        newfd = self.lastfd + 1
        if newfd > sys.maxint: newfd = 1
        if self.fdmap.has_key(newfd):
            newfd += 1
            if newfd > sys.maxint:
                newfd = 1
            if newfd == self.lastfd:
                raise Exception
        self.lastfd = newfd
        return newfd
    
    def new_dir(self, parent):
        t = {}
        t['.'] = t
        t['..'] = parent
        return t
    
    def find_node_or_parent(self, path, parent):
        currently_at = start_at = self.root
        split_path = path.split("/")
        if parent: split_path = split_path[:-1]
        try:
            for node in split_path:
                if node == "" or node == ".": continue
                if type(currently_at) is not dict: raise Exception
                currently_at = currently_at[node]
            return currently_at
        except:
            return None
        
    def find_parent(self, path):
        return self.find_node_or_parent(path, 1)
    
    def find_node(self, path):
        return self.find_node_or_parent(path, 0)
    
    def basename(self, path):
        split_path = path.split("/")
        return split_path[-1]
    
    def connect(self, service, user, arg):
        print >> sys.stderr, "Someone connected! Service = %s, User = %s, Pid = %i, initobj = %s" \
            % ( service, user, os.getpid(), arg )
        return 0
    
    def disconnect(self, ):
        return
    
    def getdir(self, path):
        found = self.find_node(path)
        if not found or type(found) is not dict: return -1
        return found.keys()
    
    def fstat(self, fd):
        if self.fdmap.has_key(fd):
            return self.stat(self.fdmap[fd]['name'], 0)
        return -1
    
    def stat(self, path, do_lstat):
        node = self.find_node(path)
        if node is not None:
            if type(node) is bytearray:
                return { "st_mode": 0777, "st_ino": id(node), "st_size": len(node) }
            return { "st_mode": 0040000 | 0777, "st_ino": id(node) }
        return -1
    
    def close(self, path):
        if self.fdmap.has_key(path):
            del self.fdmap[path]
            return 0
        return -1
    
    def open(self, path, flags, mode):
        # existing
        #try:
        node = self.find_node(path)
        if node is not None:
            fd = self.alloc_fd()
            self.fdmap[fd] = { 'name': path, 'off': 0 }
            return fd
        # new
        parent = self.find_parent(path)
        if parent is not None:
            fname = self.basename(path)
            parent[fname] = bytearray()
            fd = self.alloc_fd()
            self.fdmap[fd] = { 'name': path, 'off': 0 }
            return fd
        return -1
        #except:
        #    return -1
    
    def unlink(self, path):
        if self.find_node(path) is None: return -1
        del self.find_parent(path)[self.basename(path)];
        return 0
    
    def read(self, fd, size):
        try:
            fdinfo = self.fdmap[fd]
            node = self.find_node(fdinfo['name'])
            r = node[fdinfo['off']:fdinfo['off'] + size]
            fdinfo['off'] = fdinfo['off'] + size
            if fdinfo['off'] > len(node): fdinfo['off'] = len(node)
            return r
    
        except Exception as e:
            print >> sys.stderr, "Read returning -1 because of ", e
            return -1
    
    def write(self, fd, data):
        try:
            fdinfo = self.fdmap[fd]
            node = self.find_node(fdinfo['name'])
            node[fdinfo['off'] : fdinfo['off'] + len(data)] = data
            fdinfo['off'] = fdinfo['off'] + len(data)
            return len(data)
    
        except Exception as e:
            print >> sys.stderr, "Write returning -1 because of ", e
            return -1
    
    def pwrite(self, fd, data, offset):
        try:
            fdinfo = self.fdmap[fd]
            node = self.find_node(fdinfo['name'])
            node[offset : offset + len(data)] = data
            return len(data)
    
        except Exception as e:
            print >> sys.stderr, "Write returning -1 because of ", e
            return -1
    
    
    def lseek(self, fd, where, whence):
        try:
            fdinfo = self.fdmap[fd]
            node = self.find_node(fdinfo['name'])
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
    
    def diskfree(self, path):
        return { "size": 1024*1024*1024*10, "used": 2048 }
    
    def mkdir(self, path, mode):
        # existing
        if self.find_node(path) is not None:
            print >> sys.stderr, "mkdir path is not None"
            return -1
        # new
        parent = self.find_parent(path)
        if parent is not None:
            parent[self.basename(path)] = self.new_dir(parent)
            return 0
        print >> sys.stderr, "mkdir parent is None"
        return -1
    
    
    def unlink(self, path):
        try:
            parent = self.find_parent(path)
            del parent[self.basename(path)]
            return 0
    
        except Exception as e:
            return -1

    def rename(self, src, dst):
        if self.find_node(src) is None:
            print >> sys.stderr, "src doesn't exist!"
            self.vfs_errno = ENOENT
            return -1
        if self.find_node(dst) is not None:
            print >> sys.stderr, "dst exists!"
            self.vfs_errno = EEXISTS
            return -1

        dst_parent = self.find_parent(dst)
        src_parent = self.find_parent(src)

        dst_parent[self.basename(dst)] = src_parent[self.basename(src)]
        del src_parent[self.basename(src)]

        return 0

# main
daemon = Pyro4.Daemon(port=5559) #unixsocket="mem_fs")
uri = daemon.register(mem_fs(), "mem_fs")
print "uri=",uri
daemon.requestLoop()

