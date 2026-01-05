leaking_list = []

class LargeObject:
    def __init__(self, size):
        self.data = [0] * size

def create_leak(size):
    obj = LargeObject(size)
    leaking_list.append(obj)

if __name__ == "__main__":
    for _ in range(100000):
        create_leak(256*1024*1024)
    while True:
        ...


