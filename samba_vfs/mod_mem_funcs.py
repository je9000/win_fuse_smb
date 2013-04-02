import sys
import re

infile = "z:\\win_fuse_smb\\samba_vfs\\vfs_mem_c_base.py"
outfile = "z:\\win_fuse_smb\\samba_vfs\\vfs_mem_c.py"

funcre = re.compile(r"def +(.+):")

with open(outfile, "w") as fo:
    with open(infile) as f:
        for line in f.readlines():
            line = line.strip("\r\n")
            m = funcre.search(line)
            print >> fo, "%s" % line
            if m:
                print >> fo, "    global p"
                print >> fo, "    return p.%s" % m.group(1)

