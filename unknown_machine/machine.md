```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void vm_execute(undefined4 param_1,undefined1 *param_2)

{
  int iVar1;
  int in_GS_OFFSET;
  undefined1 *local_14;
  
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
  for (local_14 = param_2; local_14 != (undefined1 *)0x0; local_14 = local_14 + 1) {
    switch(*local_14) {
    case 0x30:
      vm_push_0(param_1);
      break;
    case 0x31:
      vm_push_1(param_1);
      break;
    case 0x32:
      vm_pop(param_1);
      break;
    case 0x33:
      vm_add(param_1);
      break;
    case 0x34:
      vm_sub(param_1);
      break;
    case 0x35:
      vm_mul(param_1);
      break;
    case 0x36:
      vm_div(param_1);
      break;
    case 0x37:
      vm_mod(param_1);
      break;
    case 0x38:
      vm_memory_put(param_1);
      break;
    case 0x39:
      vm_memory_get(param_1);
      break;
    default:
      puts("This instruction is not implemented yet");
                    /* WARNING: Subroutine does not return */
      exit(-5);
    case 0x41:
      vm_exit(param_1);
    }
  }
  if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 main(void)

{
  undefined4 uVar1;
  int in_GS_OFFSET;
  char local_414 [1024];
  int local_14;
  undefined1 *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  setvbuf(_stdin,(char *)0x0,0,0);
  setvbuf(_stdout,(char *)0x0,0,0);
  setvbuf(_stderr,(char *)0x0,0,0);
  puts("Welcome to Unknown Machine");
  puts("Write your code and our machine will execute it");
  fgets(local_414,0x400,_stdin);
  vm_execute(vm,local_414);
  uVar1 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar1 = __stack_chk_fail_local();
  }
  return uVar1;
}
```