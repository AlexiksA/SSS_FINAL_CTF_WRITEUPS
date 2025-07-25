  id FUN_08048e02(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 local_3c;
  sockaddr local_38;
  sockaddr local_28;
  socklen_t local_18;
  __pid_t local_14;
  int local_10;
  int local_c;
  int local_8;
  
  if (param_1 != 2) {
    printf("Usage: %s <port>\n",*param_2);
    fflush(stdout);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_8 = socket(2,1,0);
  if (local_8 < 0) {
    perror("ERROR opening socket");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_3c = 1;
  iVar1 = setsockopt(local_8,1,2,&local_3c,4);
  if (iVar1 < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
  }
  bzero(&local_28,0x10);
  local_c = atoi((char *)param_2[1]);
  local_28.sa_family = 2;
  local_28.sa_data[2] = '\0';
  local_28.sa_data[3] = '\0';
  local_28.sa_data[4] = '\0';
  local_28.sa_data[5] = '\0';
  local_28.sa_data._0_2_ = htons((uint16_t)local_c);
  iVar1 = bind(local_8,&local_28,0x10);
  if (iVar1 < 0) {
    perror("ERROR on binding");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  listen(local_8,5);
  local_18 = 0x10;
  while( true ) {
    local_10 = accept(local_8,&local_38,&local_18);
    if (local_10 < 0) {
      perror("ERROR on accept");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_14 = fork();
    if (local_14 < 0) break;
    if (local_14 == 0) {
      close(local_8);
      FUN_08048d3d(local_10);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    close(local_10);
  }
  perror("ERROR on fork");
                    /* WARNING: Subroutine does not return */
  exit(1);
}



void FUN_08048b3b(int param_1)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  byte bVar6;
  char local_4f7 [15];
  undefined4 auStack_4e8 [34];
  undefined4 uStack_460;
  undefined4 local_45c [255];
  undefined4 uStack_60;
  undefined1 local_5c [64];
  undefined4 local_1c;
  code *local_18;
  int local_14;
  
  bVar6 = 0;
  local_4f7[0xd] = 'I';
  local_4f7[0xe] = 'f';
  auStack_4e8[0]._0_1_ = ' ';
  auStack_4e8[0]._1_1_ = 'y';
  uStack_460 = 0xa0a;
  iVar2 = -(int)auStack_4e8;
  pcVar3 = "If you arrived here on your own, then it means you have considerable shellcoding skills. \n\nLet\'s see if you can find a flag... blindfolded.\n\n"
           + -(int)(local_4f7 + iVar2 + 0xd);
  puVar4 = auStack_4e8;
  for (uVar1 = (uint)((int)local_45c + iVar2) >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar4 = *(undefined4 *)pcVar3;
    pcVar3 = pcVar3 + 4;
    puVar4 = puVar4 + 1;
  }
  builtin_strncpy(local_4f7,"Shellcode: ",0xc);
  local_4f7[0xc] = 0;
  dup2(param_1,1);
  dup2(param_1,2);
  dup2(param_1,0);
  close(param_1);
  printf("%s",local_4f7 + 0xd);
  fflush(stdout);
  printf("%s",local_4f7);
  fflush(stdout);
  local_14 = open("flag",0);
  read(local_14,local_5c,0x40);
  close(local_14);
  read(0,local_45c,0x400);
  local_18 = (code *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  *(undefined4 *)local_18 = local_45c[0];
  *(undefined4 *)(local_18 + 0x3fc) = uStack_60;
  iVar2 = (int)local_18 - (int)((uint)(local_18 + 4) & 0xfffffffc);
  puVar4 = (undefined4 *)((int)local_45c - iVar2);
  puVar5 = (undefined4 *)((uint)(local_18 + 4) & 0xfffffffc);
  for (uVar1 = iVar2 + 0x400U >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + (uint)bVar6 * -2 + 1;
    puVar5 = puVar5 + (uint)bVar6 * -2 + 1;
  }
  mprotect(local_18,0x1000,5);
  prctl(0x26,1);
  prctl(4,0);
  local_1c = seccomp_init(0);
  seccomp_rule_add(local_1c,0x7fff0000,0xad,0);
  seccomp_rule_add(local_1c,0x7fff0000,1,0);
  seccomp_load(local_1c);
  (*local_18)();
  seccomp_release(local_1c);
  return;
}


