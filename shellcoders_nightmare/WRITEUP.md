# Shellcoder's Nightmare (sn_server) — Write-up

**Category:** pwn (shellcoding under seccomp / side-channel exfiltration)
**Binary:** `sn_server` — ELF 32-bit (i386), stripped, forking TCP server
**Support:** `libseccomp.so.2`
**Remote:** `141.85.224.104:33335`

## The challenge

`sn_server` is a forking TCP server. The per-connection handler
(`FUN_08048b3b`) does the following:

```c
fd = open("flag", O_RDONLY);
read(fd, flagbuf, 0x40);        // FLAG is read onto the STACK, before our frame
close(fd);
read(0, shellcode, 0x400);      // our shellcode
// copy shellcode into an RWX mmap, mprotect RX
prctl(PR_SET_NO_NEW_PRIVS, 1);
prctl(PR_SET_DUMPABLE, 0);
seccomp_init(SCMP_ACT_KILL);                 // default = KILL
seccomp_rule_add(..., 173 /* rt_sigreturn */, 0);
seccomp_rule_add(..., 1   /* exit */,         0);
seccomp_load();
shellcode();                     // ebp still points at the handler frame
```

So when our shellcode runs:

* The **flag is sitting on the stack** at `[ebp-0x58 .. ebp-0x18)` and `ebp` is
  still valid — we can *read* it freely.
* **seccomp only allows `exit` (1) and `rt_sigreturn` (173)**. Every other
  syscall — including `write`, `open`, `socket`, `execve` — is an instant
  `SIGKILL`. We cannot *print* or *send* anything.

This is the "nightmare": we can read the flag but have no legal way to output
it.

## The exfiltration primitive — a timing oracle

The connection is wrapped by a double-fork helper (`FUN_08048d3d`):

* the **grandchild** runs our shellcode;
* the **middle process** does `alarm(2); pause();`

The two possible timelines:

* shellcode **exits quickly** → `SIGCHLD` → the wrapper tears the connection
  down → the client sees socket **EOF after ~0 s**;
* shellcode **spins forever** → the `alarm(2)` fires after 2 s → the wrapper
  `kill(9)`s it → the client sees socket **EOF after ~2 s**.

That is a clean 1-bit oracle per connection: **fast EOF = 0, slow EOF = 1**.

## Leaking the flag bit by bit

For flag byte `i` (at `[ebp-(0x58-i)]`) and bit `b`, send shellcode that:

```asm
    mov  al, [ebp-off]      ; off = 0x58 - i
    test al, 1<<b
    jnz  spin               ; bit set -> spin -> killed at ~2 s  -> "1"
    xor  ebx, ebx
    mov  eax, 1             ; SYS_exit (allowed) -> fast EOF       -> "0"
    int  0x80
spin:
    jmp  spin               ; no syscall -> alarm(2) -> kill(9)
```

Only the two whitelisted syscalls (`exit`, and implicitly nothing in the spin
branch) are used, so seccomp never kills us for an illegal call — the spin is
killed by the *wrapper's* alarm, which is exactly the slow signal we want.

The client opens one connection per `(byte, bit)` pair, measures time-to-EOF,
and reconstructs the flag. `0x40` bytes × 8 bits = 512 connections. Concurrency
is kept low (`WORKERS = 6`) because the listen backlog is only 5 and too many
simultaneously-spinning children starve the CPU and smear the timings.
Threshold: `dt > 1.0 s ⇒ bit = 1`.

## Run it

```bash
python3 exp_sn_server.py                 # uses the host/port baked into the script
python3 exp_sn_server.py <HOST> <PORT>   # override target
```

It prints the raw flag bytes (hex) and the decoded flag, trimmed at the first
NUL/newline.

## Key takeaways

* A sandbox that forbids all output does not forbid *observable side effects*.
  Process lifetime, visible through the connection's EOF timing, is a reliable
  covert channel.
* "No write syscall" ⇒ think oracles: time, crash/no-crash, resource exhaustion.
* Leaving the secret on the stack with the frame pointer intact is the real
  mistake here; seccomp alone can't protect data the attacker's code can read.
