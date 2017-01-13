import struct

def qword(v):
    return struct.pack("<Q", v)

def recvline(s):
    import select

    buf = ""

    while True:
        select.select([s],[],[s])
        buf += s.recv(1)

        if "\n" in buf:
            return buf

class Pattern(object):
    def __init__(self, pattern, adjust):
        self.raw_pattern = pattern
        self.adjust = adjust
        self.pattern = []
        self.masked = []

        self._compile()

    def _compile(self):
        clean = self.raw_pattern.replace(" ", "")

        if len(clean) == 0 or len(clean) % 2 == 1:
            raise ValueError("Invalid pattern format (empty or not an even number of bytes)")

        for i in range(len(clean)/2):
            byte = clean[i*2:i*2+2]

            if byte == "??":
                self.masked.append(True)
                self.pattern.append(None)
            else:
                self.masked.append(False)
                self.pattern.append(int(byte, 16))

    def __len__(self):
        return len(self.pattern)

    def __getitem__(self, i):
        return self.pattern[i]

