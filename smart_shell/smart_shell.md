
undefined8 valid_shellcode(char *param_1)

{
  char *pcVar1;
  undefined *local_28 [3];
  uint local_10;
  uint local_c;
  
  local_10 = 3;
  local_28[0] = &DAT_00100a08;
  local_28[1] = &DAT_00100a0d;
  local_28[2] = &DAT_00100a10;
  local_c = 0;
  while( true ) {
    if (local_10 <= local_c) {
      return 1;
    }
    pcVar1 = strstr(param_1,local_28[local_c]);
    if (pcVar1 != (char *)0x0) break;
    local_c = local_c + 1;
  }
  return 0;
}
