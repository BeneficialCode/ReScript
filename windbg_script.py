import os 
import sys 
import time 
import shutil 
import tempfile 
import subprocess 
def log(msg): 
    sys.stdout.write("[+] %s\n" % msg)

def startInst(baseAddr, val): 
    fd = tempfile.NamedTemporaryFile(delete=False)
    fd.write(b'bp 0x%08x ".printf \\"Loop counter in 0x1170: %%08x\\\\n\\", eax; gc"\n' % (baseAddr + 0x11c3)) 
    fd.write(b'bp 0x%08x ".printf \\" Loop counter=%%08x\\\\n\\", eax; .if (@eax = 0x10) { r eax=0x20; }; gc"\n' % (baseAddr + 0x18c0)) 
    fd.write(b'bp 0x%08x ".printf \\"Changing output to %02x\\\\n\\"; r eax=0x%02x; gc"\n' % (baseAddr + 0x1db4, val, val)) 
    fd.write(b'g\n') 
    fd.close() 
    argv = [ 
    r'D:\WinDbg\x86\cdb.exe', 
    '-G', 
    '-cf', fd.name, 
    'K:\ReScript\C11.exe', '205'] 
    p = subprocess.Popen(argv) 
    try: 
        log("cdb is running...") 
        while p.poll() is None: 
            pass 
    finally: 
        while p.poll() is None: 
            log("cdb still running. Terminating process...") 
    p.terminate() 
    os.unlink(fd.name) 
for i in range(0, 16): 
    startInst(0x400000, i)
    shutil.copyfile('secret.jpg', 'secret_%i.jpg' % i) 