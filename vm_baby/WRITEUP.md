# VM Baby — Write-up

**Category:** reversing (crackme / stack VM)
**Binary:** `vm_baby` — ELF 64-bit (x86-64), not stripped

## The challenge

`main()` reads a candidate flag with `fgets(input, 0x100)`, strips the trailing
newline, and requires `strlen(input) == 0x2a` (**42 bytes**). It then calls
`run_vm(input)`:

* `run_vm != 0` → `"Flag accepted! Well done!"`
* `run_vm == 0` → `"Invalid flag. The VM has spoken."`

So we must find the 42-byte input for which `run_vm` returns non-zero.

## The VM

`run_vm` is a stack machine over a 64-byte stack, interpreting a **fixed**
bytecode program of `0x153` bytes embedded at `.rodata 0x402020`. Opcodes:

| Byte  | Operands | Effect                                        |
|-------|----------|-----------------------------------------------|
| `01`  | `c`      | push immediate `c`                            |
| `02`  | `i`      | push `input[i]`                               |
| `03`  | —        | `b = pop; a = pop; push(a == b)`              |
| `04`  | —        | `b = pop; a = pop; push(a & b)`               |
| `05`  | `k`      | `a = pop; push(a ^ k)`                        |
| `06`  | —        | `return pop()`                                |
| other | —        | `return 0` (default)                          |

## The program is a per-byte equation

Reading the bytecode, the structure is completely regular. It starts with
`push 1` (an accumulator seeded true), then repeats the same five-opcode block
for each flag byte `i`:

```
01 c_i      ; push constant c_i
02 i        ; push input[i]
05 k_i      ; xor with k_i      -> (input[i] ^ k_i)
03          ; eq                -> (input[i] ^ k_i) == c_i
04          ; and into acc      -> acc &= result
```

and finishes with `06` (return accumulator). The whole VM therefore computes:

```
run_vm(input) = AND over all i of  [ (input[i] ^ k_i) == c_i ]
```

which is non-zero **iff** for every `i`:

```
input[i] ^ k_i == c_i      <=>      input[i] = c_i ^ k_i
```

Every `(c_i, i, k_i)` triple is sitting right there in the bytecode. There is
nothing to brute force — we just read the constants and XOR them.

## Solver

`solve_vm_baby.py` reads the `0x153` bytes of bytecode straight out of the
binary, walks the regular `01 c / 02 i / 05 k / 03 / 04` blocks, and for each
sets `flag[i] = c_i ^ k_i`:

```bash
python3 solve_vm_baby.py
# flag (42 bytes): <the flag>
```

The 42-byte result is exactly the required length, confirming the recovered
input is the flag.

## Key takeaways

* Custom VMs are just an indirection layer — recover the opcode semantics once
  and the "protection" collapses into plain arithmetic.
* A per-character `(xor, equals, and-accumulate)` check is algebraically
  invertible: `input[i] = c_i ^ k_i`. No search needed.
* `shellcode.md` in this folder is the raw Ghidra byte listing of the embedded
  program, kept for reference.
