# Triple AES (hahaha) — Write-up

**Category:** crypto / reversing
**Binary:** `triple_aes` — ELF 64-bit (x86-64), PIE, not stripped, links OpenSSL
(`libcrypto` EVP API)

## The challenge

`triple_aes` prints:

```
Provide the three passphrases to unlock the flag.
Passphrase 1:
Passphrase 2:
Passphrase 3:
```

Each passphrase is read with `fgets` (newline stripped), and the flag is
"triple-encrypted" with AES-256-CBC — recovering it needs all three passphrases.

## Stage 1 — the three passphrase gates

For each `i` in `0,1,2` the binary computes `SHA-512(passphrase_i)` (via the
local `sha512_bytes` helper, which wraps `EVP_DigestInit/Update/Final` with
`EVP_sha512`) and compares it, 64 bytes at a time, against a hard-coded digest:

```
SHA512(passphrase_1) == g_digest_1    (@ 0x2180)
SHA512(passphrase_2) == g_digest_2    (@ 0x2140)
SHA512(passphrase_3) == g_digest_3    (@ 0x2100)
```

(`DIGESTS[]` at `0x3db0` is just an array of pointers to those three digests.)
A single mismatch prints `Wrong passphrase N. Access denied.` and exits with
code 1. The passphrases themselves are **not** in the binary — only their
SHA-512 digests.

The three target digests (extracted from the binary):

```
g_digest_1 = 9621e1356cfd38d5c5c3e71e42dd5857224ef059bafd768275d5279b328811a2
             6255f140076b97fd353e358882430296f9dabb1cd657500bac06d80d943ade4d
g_digest_2 = 40abb5e1b1ab6029f98b5a37dd1be8af426db05f9484894fc248001fa91b9d35
             a23595d714e628b79f1cf883311dfa450b619d672fcfbef5d291c01759c4b613
g_digest_3 = 4e041fafbd87e16f37580012c7c42253c0811e6110c629fc19614621a72911dd
             33e2c1fff6269251b6e79eea7b99ca7b83b1c71d595bd9c35390e8a8e971a4cb
```

### Recovering the passphrases

Since only the digests are stored, this stage is an **offline dictionary /
brute-force** against unsalted SHA-512. Put the three hashes in a file and run,
e.g.:

```bash
printf '%s\n%s\n%s\n' \
  9621e1356cfd38d5...943ade4d \
  40abb5e1b1ab6029...59c4b613 \
  4e041fafbd87e16f...e971a4cb > digests.txt

hashcat -m 1700 -a 0 digests.txt rockyou.txt      # SHA-512, straight wordlist
# or:  john --format=raw-sha512 --wordlist=rockyou.txt digests.txt
```

(`-m 1700` is hashcat's "SHA2-512" mode.) They are not simple numeric PINs or
the obvious small wordlist candidates, so a real wordlist (rockyou + rules) is
the intended path.

## Stage 2 — the triple AES-256-CBC decryption

After all three gates pass, the binary prints
`All passphrases accepted. Decrypting...` and runs an 80-byte embedded
ciphertext (`g_ciphertext @ 0x21c0`) through **three** AES-256-CBC
decryptions, applying the passphrases in **reverse order** (`pass3`, then
`pass2`, then `pass1` — the loop counter runs `2,1,0`). For each layer `i`:

```
key = SHA256(passphrase_i)         # 32 bytes -> AES-256
iv  = SHA512(passphrase_i)[:16]    # first 16 bytes of the SHA-512 digest
```

Padding is **enabled** (`EVP_CIPHER_CTX_set_padding(ctx, 1)` → PKCS#7), and the
plaintext of one layer is fed as the ciphertext of the next. The final
plaintext is printed as `Flag: %.*s`.

Embedded ciphertext (extracted from the binary):

```
g_ciphertext =
  86ab96f5ef0a675f7608323c93b71b9a73738eb7e01d81c81e845b77943d261b
  bfaef6f125fb8a808a7461398241baa99958a226532c299b6ae952e4fcaa05b0
  629daf3de4c28d336e36f7efa18a9d33
```

## Solver

`solve_triple_aes.py` hard-codes the three digests and the ciphertext. Once the
passphrases are cracked, drop them into `PASSPHRASES` and it:

1. verifies `SHA512(passphrase_i) == g_digest_i` (same check as the binary), and
2. performs the reverse-order triple AES-256-CBC decrypt with
   `key = SHA256(p)` / `iv = SHA512(p)[:16]`, then PKCS#7-unpads,

reproducing the flag offline without touching the service:

```bash
python3 solve_triple_aes.py        # prints crack instructions until PASSPHRASES is set
```

## Key takeaways

* Layering three AES encryptions adds no meaningful security when every layer's
  key/IV is derived deterministically from a passphrase — the whole scheme is
  only as strong as the **weakest passphrase** against a dictionary attack.
* Unsalted SHA-512 password gates are directly crackable with hashcat/john; the
  binary even hands you the exact target digests.
* The non-obvious details that make or break the solve: the passphrases are
  applied in **reverse** order, the IV is the **first 16 bytes of SHA-512**
  (not SHA-256), and padding is **on**.
