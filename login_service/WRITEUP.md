# Login Service — Write-up

**Category:** pwn (format string)
**Binary:** `login_service` — ELF 32-bit (i386), stripped, dynamically linked
**Remote:** `141.85.224.104` (login service)

## The challenge

The program greets the user, reads a **Username**, then a **Password**, and
behaves like a trivial login prompt. The interesting part is a function pointer
that lives on the stack, guarding a `call`.

Reconstructed `main()`:

```c
void (*fp)(const char *) = (void *)0x8048420;   // = system@plt, stored at [ebp-0xc]
char *greet;                                     // "Hello, " + username

puts("Username: ");
fgets(username, n, stdin);

strcpy(greet, "Hello, ");
strcat(greet, username);
printf(greet);                 // <-- FORMAT STRING BUG: user controls the format

puts("Password: ");
fgets(password, n, stdin);

if (fp != (void *)0x8048420) {           // pointer was changed?
    puts("That was hard, sheesh");
    fp("cat /etc/hostname");             // 0x804878c = "cat /etc/hostname"
}
return 0;
```

Two things to notice from the disassembly:

* `[ebp-0xc]` is initialised to `0x8048420`, which is **`system@plt`**.
* `printf(greet)` is called with an attacker-influenced string (`"Hello, " +
  username`) as the **format** argument — a classic uncontrolled format string.
* The guarded branch only runs when `[ebp-0xc] != 0x8048420`, and it calls the
  pointer with the argument `"cat /etc/hostname"`.

## The bug — arbitrary write via `%n`

Because the username is used as a `printf` *format*, we get the full
format-string toolbox:

* `%x` / `%p` leak stack words (used first to find which `%N$` argument index
  maps to our controlled buffer — the probe showed offset **3**);
* `%hhn` / `%hn` / `%n` perform **writes** of the running output-character count
  to an address taken from the stack.

The "Hello, " prefix (7 bytes) plus one padding byte means 8 characters are
already printed before our controlled data begins, which the exploit accounts
for when computing padding so each `%hhn` fires with the correct cumulative
count.

## Exploitation

The target is the saved function pointer at `[ebp-0xc]`. We place the address of
that slot in our buffer (split so its bytes land in known `%N$` positions), then
use width-padded `%hhn`/`%hn` writes to set it to a value **different from
`0x8048420`**. Any change makes the `!=` check true, so the guarded branch runs
and the pointer is invoked as `fp("cat /etc/hostname")`:

* Steering the pointer back to a `system`-equivalent address turns the branch
  into `system("cat /etc/hostname")` — command execution with the fixed
  argument baked into the binary.
* The success signal is the `"That was hard, sheesh"` line, which only prints
  once the write has landed and the pointer no longer equals `system@plt`.

The working one-shot format payload used in `exp.py`:

```
%1$26723x%67$n%1$7085x%3$hn%1$33764x%4$hn
```

This uses positional arguments to pad the byte counter to the required values
and then performs the staged 16-bit `%hn` writes into the pointer slot (plus a
`%n` auxiliary write), flipping the guard so the `call` fires.

## Run it

```bash
python3 exp.py
# look for: "That was hard, sheesh"  => the write landed and the guard flipped
```

(Stack addresses are environment-sensitive on i386; if the exact slot address
drifts, re-run the `%p` probe to recover the offset and the pointer's stack
address, then recompute the padding widths.)

## Key takeaways

* `printf(user_input)` is never safe — even "just a greeting" becomes an
  arbitrary read/write primitive.
* Storing a *code pointer* on the stack next to attacker data and gating a
  `call` on it hands the attacker control flow the moment a write primitive
  exists.
* You don't always need a full EIP overwrite: flipping one guarded function
  pointer is enough to reach the intended `system(...)` call.
