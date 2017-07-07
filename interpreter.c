#include "ebpf.h"
#include <stdio.h>

int main(int argc, char const *argv[]) {
  if (argc < 3){
    printf("Usage: interpreter [elf file] [entry function] [memory file(optional)]\n");
    return -1;
  }
  const char * binary_file = argv[1];
  runtime_t runtime;
  load_elf_file(&runtime, binary_file);

  if (argc == 4){
    const char * memory_file = argv[3];
    load_mem_file(&runtime, memory_file);
  }else
    runtime.mem = (char*)malloc(sizeof(char) * MAX_MEM_SIZE);

  const char * entry_function = argv[2];

  uint64_t ret = execution(&runtime, entry_function);
  printf("Execution Result:\n0x%08x\n", (unsigned int)ret);

  cleanup(&runtime);
  return 0;
}
