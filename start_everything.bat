cd reflector
start start_reflector_c.bat
cd ..
start python samba_vfs/vfs_mem_s.py
PATH=%PATH%;c:\cygwin\bin
cd ..\smb\sbin
smbd.exe -FS

