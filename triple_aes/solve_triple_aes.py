#!/usr/bin/env python3
# Solver for ./triple_aes  (crypto / reversing)
#
# main() logic (see WRITEUP.md for the full disassembly walk-through):
#
#   1. Three passphrases are read with fgets (newline stripped).  For each one,
#      SHA-512(passphrase) is compared against a hard-coded digest:
#          SHA512(pass1) == g_digest_1
#          SHA512(pass2) == g_digest_2
#          SHA512(pass3) == g_digest_3
#      A single mismatch prints "Wrong passphrase N" and exits.
#
#   2. Once all three are accepted it "triple-decrypts" an 80-byte embedded
#      ciphertext (g_ciphertext) with AES-256-CBC, padding ENABLED (PKCS#7),
#      applying the passphrases in REVERSE order (pass3, then pass2, then pass1).
#      For layer i:
#          key = SHA256(passphrase_i)            (32 bytes -> AES-256)
#          iv  = SHA512(passphrase_i)[:16]       (first 16 bytes)
#      The plaintext of one layer is the ciphertext of the next.
#      The final plaintext is printed as  "Flag: %.*s".
#
# The passphrases themselves are NOT in the binary, only their SHA-512 digests.
# Recovering them is an offline dictionary/brute problem, e.g.:
#       hashcat -m 1700 digests.txt rockyou.txt
# Fill in PASSPHRASES below once cracked and this script reproduces the flag
# locally without touching the service.

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ---- hard-coded data extracted from the binary -------------------------------
G_DIGEST_1 = bytes.fromhex(
    "9621e1356cfd38d5c5c3e71e42dd5857224ef059bafd768275d5279b328811a2"
    "6255f140076b97fd353e358882430296f9dabb1cd657500bac06d80d943ade4d")
G_DIGEST_2 = bytes.fromhex(
    "40abb5e1b1ab6029f98b5a37dd1be8af426db05f9484894fc248001fa91b9d35"
    "a23595d714e628b79f1cf883311dfa450b619d672fcfbef5d291c01759c4b613")
G_DIGEST_3 = bytes.fromhex(
    "4e041fafbd87e16f37580012c7c42253c0811e6110c629fc19614621a72911dd"
    "33e2c1fff6269251b6e79eea7b99ca7b83b1c71d595bd9c35390e8a8e971a4cb")

G_CIPHERTEXT = bytes.fromhex(
    "86ab96f5ef0a675f7608323c93b71b9a73738eb7e01d81c81e845b77943d261b"
    "bfaef6f125fb8a808a7461398241baa99958a226532c299b6ae952e4fcaa05b0"
    "629daf3de4c28d336e36f7efa18a9d33")

DIGESTS = [G_DIGEST_1, G_DIGEST_2, G_DIGEST_3]

# ---- fill these in after cracking the SHA-512 digests ------------------------
#   PASSPHRASES = [b"pass_one", b"pass_two", b"pass_three"]
PASSPHRASES = None
# -----------------------------------------------------------------------------


def check_passphrases(passes):
    for i, p in enumerate(passes):
        if hashlib.sha512(p).digest() != DIGESTS[i]:
            raise ValueError("passphrase %d does not match g_digest_%d" % (i + 1, i + 1))
    print("[+] all three passphrases match the stored SHA-512 digests")


def triple_decrypt(passes):
    data = G_CIPHERTEXT
    # applied in reverse order: pass3, pass2, pass1  (matches r12 = 2,1,0)
    for p in reversed(passes):
        key = hashlib.sha256(p).digest()        # AES-256 key
        iv = hashlib.sha512(p).digest()[:16]    # IV = first 16 bytes of SHA512
        data = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    return unpad(data, 16)


if __name__ == "__main__":
    if PASSPHRASES is None:
        print(__doc__)
        print("[!] PASSPHRASES not set. Crack the digests first, e.g.:")
        print("      printf '%s\\n%s\\n%s\\n' \\\n"
              "        %s \\\n        %s \\\n        %s > digests.txt" % (
                  G_DIGEST_1.hex(), G_DIGEST_2.hex(), G_DIGEST_3.hex(),
                  G_DIGEST_1.hex(), G_DIGEST_2.hex(), G_DIGEST_3.hex()))
        print("      hashcat -m 1700 -a 0 digests.txt rockyou.txt")
        raise SystemExit(0)

    check_passphrases(PASSPHRASES)
    flag = triple_decrypt(PASSPHRASES)
    print("[+] Flag:", flag.decode(errors="replace"))
