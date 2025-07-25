
undefined1 run_vm(long param_1)

{
  int iVar1;
  undefined1 uVar2;
  undefined1 local_58 [64];
  undefined4 local_18;
  char local_13;
  char local_12;
  byte local_11;
  byte local_10;
  byte local_f;
  byte local_e;
  undefined1 local_d;
  int local_c;
  
  local_18 = 0xffffffff;
  local_c = 0;
  while (local_c < 0x153) {
    iVar1 = local_c + 1;
    local_d = bytecode[local_c];
    switch(local_d) {
    default:
      return 0;
    case 1:
      local_c = local_c + 2;
      push(local_58,bytecode[iVar1]);
      break;
    case 2:
      local_c = local_c + 2;
      push(local_58,*(undefined1 *)(param_1 + (ulong)(byte)bytecode[iVar1]));
      break;
    case 3:
      local_c = iVar1;
      local_12 = pop(local_58);
      local_13 = pop(local_58);
      push(local_58,local_12 == local_13);
      break;
    case 4:
      local_c = iVar1;
      local_10 = pop(local_58);
      local_11 = pop(local_58);
      push(local_58,local_10 & local_11);
      break;
    case 5:
      local_c = iVar1;
      local_e = pop(local_58);
      local_f = bytecode[local_c];
      local_c = local_c + 1;
      push(local_58,local_e ^ local_f);
      break;
    case 6:
      local_c = iVar1;
      uVar2 = pop(local_58);
      return uVar2;
    }
  }
  return 0;
}