import os
import multiprocessing
from time import sleep

def func(dir):
    for i in range(5):
        print("writing to file %s/%d!\n"  % (dir, i))
        os.system("dd if=/dev/zero of=%s/%d bs=1G count=20" % (dir, i))

    for i in range(5):
        print("deleting file %d" % i)
        os.system("rm %s/%d" % (dir, i))
    sleep(1000)



if __name__=="__main__":
    loc = "/path/to/store/trashbin"
    procs = []
    for i in range(10):
        p = multiprocessing.Process(target=func, args=(loc+str(i), ))
        procs.append(p)
    # print(len(procs))
    for p in procs:
        p.start()
    try:
        sleep(100000)
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()