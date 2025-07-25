undefined8 run_session(void)

{
  int iVar1;
  undefined8 uVar2;
  uint local_2c;
  size_t local_28;
  size_t local_20;
  byte *local_18;
  void *local_10;
  
  local_10 = malloc(0x40);
  if (local_10 == (void *)0x0) {
    puts("malloc failed");
    uVar2 = 0xffffffff;
  }
  else {
    local_18 = (byte *)malloc(0x20);
    if (local_18 == (byte *)0x0) {
      free(local_10);
      puts("malloc failed");
      uVar2 = 0xffffffff;
    }
    else {
      *local_18 = 0xab;
      local_18[4] = 3;
      local_18[5] = 0;
      local_18[6] = 0;
      local_18[7] = 0;
      *(void **)(local_18 + 8) = local_10;
      local_18[0x10] = 0;
      local_18[0x11] = 0;
      local_18[0x12] = 0;
      local_18[0x13] = 0;
      local_18[0x14] = 0;
      local_18[0x15] = 0;
      local_18[0x16] = 0;
      local_18[0x17] = 0;
      *(code **)(local_18 + 0x18) = default_output;
      printf("CipherBox ready. Key: 0x%02x, Rounds: %u\n",(ulong)*local_18,
             (ulong)*(uint *)(local_18 + 4));
      printf("Enter message length: ");
      fflush(stdout);
      local_2c = 0;
      iVar1 = __isoc99_scanf(&DAT_00402081,&local_2c);
      if (iVar1 == 1) {
        getchar();
        if (local_2c == 0) {
          puts("Empty message.");
          free(local_18);
          free(local_10);
          uVar2 = 1;
        }
        else {
          printf("Enter message (%u bytes): ",(ulong)local_2c);
          fflush(stdout);
          local_20 = fread(local_10,1,(ulong)local_2c,stdin);
          if (local_20 == 0) {
            free(local_18);
            free(local_10);
            uVar2 = 0;
          }
          else {
            *(size_t *)(local_18 + 0x10) = local_20;
            local_28 = local_20;
            if (0x40 < local_20) {
              local_28 = 0x40;
            }
            cipherbox_encrypt(local_10,local_28,*local_18,*(undefined4 *)(local_18 + 4));
            (**(code **)(local_18 + 0x18))
                      (*(undefined8 *)(local_18 + 8),*(undefined8 *)(local_18 + 0x10));
            free(local_18);
            free(local_10);
            uVar2 = 1;
          }
        }
      }
      else {
        free(local_18);
        free(local_10);
        uVar2 = 0;
      }
    }
  }
  return uVar2;
}