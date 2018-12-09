#!/bin/bash
./qemu-system-aarch64 -nographic -machine hitcon -cpu hitcon -bios bios.bin -m 3072 -monitor /dev/null -serial null -S -s
