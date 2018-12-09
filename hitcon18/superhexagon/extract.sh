# 0x0E000000: 0x2850  + 0x68
dd if=bios.bin of=secure_mem_0E000000 skip=10320 bs=1 count=104

# 0x40100000: 0x10000 + 0x10000 (64K)
dd if=bios.bin of=normal_mem_40100000 skip=65536 bs=1 count=65536

# 0x0E400000: 0x20000 + 0x90000 (576K)
dd if=bios.bin of=secure_mem_0E400000 skip=131072 bs=1 count=589824

# 0x40000000: 0xb0000 + 0x10000 (64K)
dd if=bios.bin of=normal_mem_40000000 skip=720896 bs=1 count=65536
