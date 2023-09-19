import os

print(f"Running as process ID: {os.getpid()}")

def infiniteloop():
    a = 0
    while True:
        a += 1

infiniteloop()
