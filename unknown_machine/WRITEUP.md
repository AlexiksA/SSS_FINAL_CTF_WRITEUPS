# Unknown Machine — Write-up

**Category:** pwn (binary exploitation)
**Binary:** `machine` — ELF 32-bit (i386), PIE, dynamically linked, *not* stripped
**Provided libc:** `libc.so.6` (Debian GLIBC 2.19 — this is the one the remote runs)
**Remote:** `141.85.224.104:33341`

## The challenge

`machine` implements a tiny stack-based virtual machine. `main()` reads up to
`0x400` bytes of "code" with `fgets` and hands it to `vm_execute`, which walks
the buffer one ASCII byte at a time and dispatches on the opcode:

| Opcode (ASCII) | Mnemonic   | Effect                                      |
|----------------|------------|---------------------------------------------|
| `0`            | push 0     | push constant 0                             |
| `1`            | push 1     | push constant 1                             |
| `2`            | pop        | pop                                         |
| `3`            | add        | push (top + below)                          |
| `4`            | sub        | push (top − below)                          |
| `5`            | mul        | push (top * below)                          |
| `6`            | div        | push (top / below)                          |
| `7`            | mod        | push (top % below)                          |
| `8`            | mem_put    | idx = pop; val = pop; `mem[idx] = val`      |
| `9`            | mem_get    | idx = pop; push `mem[idx]`                  |
| `A`            | exit       | `vm_exit()`                                 |

There is **no output opcode**, so any exploit is necessarily *blind*.

## The bug — signed index into VM "memory"

`vm_memory_put` / `vm_memory_get` use the popped index as a **signed byte** and
only bounds-check it with `index <= 0x3f`. A value in `0x80..0xff` is *negative*
as a signed byte, so it passes the check and lets the VM read/write dwords
**before** the `vm` structure.

The `vm` struct lives at image offset `0x4060`. Memory accesses are
`*(vm + index*4)`, so negative indices reach straight into the **GOT**, which
sits at lower addresses. Because every access is *relative to `vm`*, PIE /
ASLR is irrelevant — we never need an address leak for the write target:

```
IDX_PUTS = (0x4014 - 0x4060) / 4 = -19   # low byte 0xED -> passes signed check
IDX_EXIT = (0x4018 - 0x4060) / 4 = -18   # low byte 0xEE
```

So `mem[-19]` *is* `puts@GOT` and `mem[-18]` *is* `exit@GOT`.

## Exploitation strategy (blind, ASLR-independent)

1. **Leak nothing, compute everything relatively.** `puts@GOT` is already
   resolved to a libc address by the time our code runs. We read it onto the VM
   stack with `mem_get(-19)`, then do pure arithmetic to turn it into
   `system()` and `&"/bin/sh"` using the **fixed deltas** from the *provided*
   libc (Debian 2.19):
   * `D_SYSTEM = system - puts`
   * `D_BINSH  = &"/bin/sh" - puts`

2. **Overwrite `exit@GOT` with `system`.**
   `system = puts − |D_SYSTEM|`. Build the magnitude, push `puts`, subtract,
   then `mem_put(-18)` to write `system` over `exit@GOT`.

3. **Fire `system("/bin/sh")`.** Compute `&"/bin/sh" = puts + D_BINSH`, leave it
   on top of the stack as the argument, then execute opcode `A` (`vm_exit`).
   `vm_exit` calls `exit@plt`, which now resolves through the poisoned GOT entry
   to `system`, and the stack argument is interpreted as `system`'s first
   argument → `system("/bin/sh")`.

### Pushing arbitrary constants

The VM can only push the literals 0 and 1, so arbitrary integers are built by
**double-and-add** (binary exponentiation of the value): push the leading `1`
bit, then for each remaining bit emit `1135` (push 2 then multiply = double) and
append `13` (+1) when the bit is set. See `pushc()` in `exp_machine.py`.

## Run it

```bash
python3 exp_machine.py            # remote (default) -> 141.85.224.104:33341
python3 exp_machine.py --local    # local test against the host libc
```

The program ends with `A` (`vm_exit`) which never returns to the opcode loop,
so the trailing newline `sendline` appends is never interpreted as an illegal
opcode. Remote stdout is fully buffered, which does not matter for this blind
shell. Dropping into the shell, `cat` the flag.

## Key takeaways

* A signed/unsigned confusion in a single bounds check turns a "safe" 64-entry
  VM memory into an arbitrary read/write of adjacent sections.
* When the write target is expressed as an offset from a module symbol, you do
  not need to defeat PIE — relative GOT writes are position-independent.
* No output primitive ≠ unexploitable: GOT poisoning + `exit`-as-`system` is a
  clean blind path to a shell.
