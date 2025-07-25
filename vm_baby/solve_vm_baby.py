#!/usr/bin/env python3
# Solver for vm_baby — a stack-VM crackme.
#
# main(): fgets(input,0x100); strip '\n'; require strlen == 0x2a (42);
#         if run_vm(input) != 0  -> "Flag accepted! Well done!"  (return 0 / success)
#         else                   -> "Invalid flag. The VM has spoken."
#
# run_vm bytecode (0x153 bytes @ .rodata 0x402020) is a fixed program.
# Opcodes (stack machine over a 64-byte stack):
#   01 c : push imm c
#   02 i : push input[i]
#   03   : b=pop; a=pop; push(a == b)
#   04   : b=pop; a=pop; push(a & b)
#   05 k : a=pop; push(a ^ k)
#   06   : return pop()          (default/other opcode: return 0)
#
# The program is: push 1 (acc); then for each i:  push c_i; push input[i];
# xor k_i; eq;  and-into-acc.  So it returns 1 iff for every i:
#     (input[i] ^ k_i) == c_i    <=>    input[i] = c_i ^ k_i
#
# We just read the (c_i, i, k_i) triples straight out of the bytecode.

bc = open('vm_baby', 'rb').read()[0x2020:0x2020 + 0x153]

assert bc[0] == 1 and bc[1] == 1, "expected initial 'push 1' accumulator"
sol, j = {}, 2
while bc[j] != 6:                       # 6 == return
    assert bc[j] == 1;  c   = bc[j + 1]; j += 2   # push imm c_i
    assert bc[j] == 2;  idx = bc[j + 1]; j += 2   # push input[idx]
    assert bc[j] == 5;  k   = bc[j + 1]; j += 2   # xor k_i
    assert bc[j] == 3;  j += 1                     # eq
    assert bc[j] == 4;  j += 1                     # and
    sol[idx] = c ^ k

flag = bytes(sol[i] for i in range(max(sol) + 1))
print("flag (%d bytes): %s" % (len(flag), flag.decode()))
