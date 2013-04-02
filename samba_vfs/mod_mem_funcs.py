import sys
import re

infile = "z:\\win_fuse_smb\\samba_vfs\\vfs_mem_c_base.py"
outfile = "z:\\win_fuse_smb\\samba_vfs\\vfs_mem_c.py"

funcre = re.compile(r"def +(.+):")

with open(outfile, "w") as fo:
    with open(infile) as f:
        last_m = None
        for line in f.readlines():
            line = line.strip("\r\n")
            m = funcre.search(line)
            if len(line) > 0:
                print >> fo, "%s" % line
            if m:
                print >> fo, "    global p"
                last_m = m
            elif len(line) == 0:
                if last_m:
                    print >> fo, "    return p.%s" % last_m.group(1)
                print >> fo, ""

