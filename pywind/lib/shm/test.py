import shm
import time, os, sys

is_ok, code = shm.memnew(shm.IPC_PRIVATE, 4096, shm.IPC_CREATE | 0o777)

if not is_ok:
    print("failed")
    sys.exit(-1)
else:
    shmid = code

pid = os.fork()

if pid == 0:
    shmoper = shm.shmoper()
    rs = shmoper.at(shmid, shm.IPC_PRIVATE)
    rs = shmoper.write(b"do you like me?", 0)

    sys.exit(0)

time.sleep(1)
shmoper = shm.shmoper()
rs = shmoper.at(shmid, shm.IPC_PRIVATE)
print(rs)
print(shmoper.read(0, 20))

shm.memdel(shmid)
