import time

def log(tag, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{tag}] {msg}")
