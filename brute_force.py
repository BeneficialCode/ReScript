import subprocess
seconds = 60

for i in range(0, 255):
    cmd = 'CryptoGraph.exe %d' % i
    print(cmd)
    try:
        stdout = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=seconds)
        print(stdout)
    except subprocess.TimeoutExpired:
        pass
    