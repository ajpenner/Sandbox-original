import time

cdef unsigned long long int total = 0
cdef int k
cdef float t1
cdef float t2
cdef float t

t1 = time.time()

for k in range(1000000000):
    total = total + k
print("Total =", total)

t2 = time.time()
t = t2-t1
print("%.20f" % t)
