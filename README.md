# SSS Final CTF — Write-ups & Solutions

This repository collects my solutions and write-ups for the **final CTF of the
Security Summer School (SSS)**. Each challenge lives in its own directory
together with the original challenge binary (and any provided libraries), the
reverse-engineering notes, the exploit/solver script, and a `WRITEUP.md`
explaining the bug and the full solution.

All of these were solved as part of the SSS final capture-the-flag event; this
repo is my personal record of how each one was broken.

## Challenges

| Directory | Challenge | Category | Core idea |
|-----------|-----------|----------|-----------|
| [`unknown_machine/`](unknown_machine/WRITEUP.md) | Unknown Machine (`machine`) | pwn (i386) | Signed-index bug in a stack VM → relative GOT read/write → overwrite `exit@GOT` with `system`, blind `system("/bin/sh")` |
| [`smart_shell/`](smart_shell/WRITEUP.md) | Smart Shell | pwn (shellcoding) | `strstr` blacklist on `bin`/`sh`/`bash` bypassed by reading the flag with raw `open`/`read`/`write` syscalls instead of exec'ing a shell |
| [`shellcoders_nightmare/`](shellcoders_nightmare/WRITEUP.md) | Shellcoder's Nightmare (`sn_server`) | pwn (seccomp) | Flag on the stack but seccomp allows only `exit`/`rt_sigreturn`; leak it 1 bit per connection via a fork-wrapper **timing oracle** |
| [`login_service/`](login_service/WRITEUP.md) | Login Service | pwn (format string) | `printf(user)` format-string write flips a guarded stack function pointer into the intended `system(...)` call |
| [`vm_baby/`](vm_baby/WRITEUP.md) | VM Baby | reversing | Stack-VM crackme that reduces to `input[i] = c_i ^ k_i`; constants read straight from the bytecode |
| [`heap_cipher/`](heap_cipher/WRITEUP.md) | Heap Cipher (`maybe-hidden`) | pwn (heap) | Unbounded `fread` into a `0x40` buffer overflows an adjacent control struct → overwrite callback ptr → leak libc → `system("/bin/sh")` |
| [`triple_aes/`](triple_aes/WRITEUP.md) | Triple AES (`hahaha`) | crypto / reversing | Three SHA-512 passphrase gates (crack with hashcat) then reverse-order triple AES-256-CBC decrypt, `key=SHA256(p)`, `iv=SHA512(p)[:16]` |

## Repository layout

Every challenge directory contains some or all of:

* the **challenge binary** (and provided `libc.so.6` / `ld` / `libseccomp` when
  the exploit depends on a specific version);
* `*.md` **reverse-engineering notes** — the relevant Ghidra decompilation /
  byte listings used to understand the target;
* the **exploit or solver** — `exp_*.py` / `solve_*.py`, written with
  [pwntools](https://github.com/Gallopsled/pwntools) (and `pycryptodome` for the
  crypto one);
* `WRITEUP.md` — the full explanation: the bug, the strategy, and how to run it.

## Running the exploits

Most scripts use pwntools:

```bash
pip install pwntools pycryptodome
cd <challenge>
python3 exp_*.py            # or solve_*.py
```

Remote targets (host/port) are baked into the scripts where applicable; several
accept a `--local` / `REMOTE` switch to run against the local binary instead.
The remote endpoints point at the SSS competition infrastructure
(`141.85.224.104`, various ports) and may no longer be reachable after the
event.

## Categories at a glance

- **Binary exploitation (pwn):** Unknown Machine, Smart Shell, Shellcoder's
  Nightmare, Login Service, Heap Cipher — covering a VM GOT-overwrite, a
  shellcode filter bypass, a seccomp timing-oracle leak, a format-string write,
  and a classic heap overflow into a callback pointer.
- **Reversing:** VM Baby — a stack-VM crackme inverted algebraically.
- **Crypto:** Triple AES — password-cracking plus layered AES-256-CBC.

---

*Solutions for the final Security Summer School (SSS) CTF.*
