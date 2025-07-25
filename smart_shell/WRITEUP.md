# Smart Shell — Write-up

**Category:** pwn (shellcoding / filter bypass)
**Binary:** `smart_shell` — ELF 64-bit (x86-64), PIE, not stripped
**Remote:** `141.85.224.104:33331`

## The challenge

`main()` reads up to `0x96` (150) bytes with `fgets`, passes the buffer to
`valid_shellcode()`, and — if that returns true — **calls the buffer directly**
as code. Our input is executed as native x86-64.

```c
fgets(buf, 0x96, stdin);
if (valid_shellcode(buf))
    ((void(*)())buf)();
```

## The filter

`valid_shellcode()` rejects the input if `strstr()` finds **any** of three
ASCII substrings stored in `.rodata` (`0xa08`, `0xa0d`, `0xa10`):

```
"bash"   "sh"   "bin"
```

This is designed to block the obvious payloads. `execve("/bin/sh")` contains
both `bin` and `sh`; even `execve("/bin/cat", …)` contains `bin`. So **no
`/bin/*` exec and no shell** are allowed through the filter.

Additional byte constraints come from the input path:

* no `0x0a` byte — `fgets` stops at a newline;
* `≤ 149` bytes total;
* must not contain `bash` / `sh` / `bin` anywhere.

## The idea — don't spawn a shell, just read the flag

We never need a shell to win: we can read the flag with raw syscalls. The path
`"/home/ctf/flag"` contains **none** of the forbidden substrings, so the
shellcode is:

```
open("/home/ctf/flag", O_RDONLY, 0)   ; SYS_open  (rax=2)
read(fd, buf, 0x200)                   ; SYS_read  (rax=0)
write(1, buf, n)                       ; SYS_write (rax=1)
exit(0)                                ; SYS_exit  (rax=60)
```

The path is pushed onto the stack word-by-word (NUL-terminated, padded to 8
bytes) so `rsp` points at it; `rsi`/`rdx` are zeroed for flags/mode. The read
buffer is placed well below our own code (`rsp − 0x200`) so we don't overwrite
the executing shellcode.

The exploit assembles this with pwntools and asserts the three safety
properties before sending so the filter and `fgets` cannot truncate or reject
it (the assembled payload is comfortably under 149 bytes and newline-free).

## Run it

```bash
python3 exp_smart_shell.py            # connects to the remote in the script
```

If the real flag path differs (e.g. `/flag`), change the single `FLAG_PATH`
line — just keep it free of `bin`/`sh`/`bash`. If a literal `/flag` is ever
needed and `sh` sneaks in, build the path from registers/xor instead.

## Key takeaways

* Substring blacklists on shellcode are brittle: the "forbidden" tokens only
  matter for one specific technique (exec'ing `/bin/sh`). Raw-syscall file reads
  sidestep the entire premise.
* Know your byte constraints (`fgets` newline stop, length cap) and assert them
  in the exploit so failures are obvious.
