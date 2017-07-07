#include "ebpf.h"
#include <stdlib.h>
#include <stdio.h>

void setup(runtime_t * runtime, const char* entry_function){
  int i;
  runtime->curr_stack = (char*)malloc(sizeof(char) * MAX_STACK_SPACE) + MAX_STACK_SPACE;
  for (i = 0; i < REG_SIZE; i++)
    runtime->reg[i] = 0;
  runtime->reg[1] = (uint64_t)runtime->mem;
  runtime->reg[10] = (uint64_t)runtime->curr_stack;
  int64_t entry_offset = lookup_symbol(&(runtime->symbol_table), entry_function);
  if (entry_offset == -1){
    printf("Cannot locate entry function symbol\n");
    abort();
  }
  runtime->prog_cntr = runtime->code + entry_offset/8; //64bit/8byte instruction len
  runtime->prog_stack.curr_size = 0;
}

void mem_check(runtime_t * rt, const uint8_t * access, size_t access_size){
  if (access + access_size <= rt->mem + MAX_MEM_SIZE && access >= rt->mem) return;
  if (access + access_size <= rt->curr_stack && access >= rt->curr_stack - MAX_STACK_SPACE) return;
  printf("Illegal memory access\n");
  abort();
}

uint64_t execution(runtime_t * rt, const char* entry_function){
  char symbol_name[100];
  uint64_t ret_addr;
  setup(rt, entry_function);
  while(1){
    if (rt->prog_cntr >= rt->code + rt->instruction_size){
      printf("End of program without exit statement\n");
      abort();
    }
    rt->reg[10] = (uint64_t)rt->curr_stack;
    switch (rt->prog_cntr->opcode) {
      case OP_ADD_IMM:
        rt->reg[rt->prog_cntr->dst] += rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_ADD_REG:
        rt->reg[rt->prog_cntr->dst] += rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_SUB_IMM:
        rt->reg[rt->prog_cntr->dst] -= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_SUB_REG:
        rt->reg[rt->prog_cntr->dst] -= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;

      case OP_MUL_IMM:
        rt->reg[rt->prog_cntr->dst] *= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_MUL_REG:
        rt->reg[rt->prog_cntr->dst] *= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_DIV_IMM:
        if (!rt->prog_cntr->imm){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] /= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_DIV_REG:
        if (!rt->prog_cntr->src){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] /= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_OR_IMM:
        rt->reg[rt->prog_cntr->dst] |= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_OR_REG:
        rt->reg[rt->prog_cntr->dst] |= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_AND_IMM:
        rt->reg[rt->prog_cntr->dst] &= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_AND_REG:
        rt->reg[rt->prog_cntr->dst] &= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_LSH_IMM:
        rt->reg[rt->prog_cntr->dst] <<= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_LSH_REG:
        rt->reg[rt->prog_cntr->dst] <<= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_RSH_IMM:
        rt->reg[rt->prog_cntr->dst] = (uint32_t)(rt->reg[rt->prog_cntr->dst]) >> rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_RSH_REG:
        rt->reg[rt->prog_cntr->dst] = (uint32_t)(rt->reg[rt->prog_cntr->dst]) >> rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_NEG:
        rt->reg[rt->prog_cntr->dst] = -rt->reg[rt->prog_cntr->dst];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_MOD_IMM:
        if (!rt->prog_cntr->imm){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] %= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_MOD_REG:
        if (!rt->prog_cntr->src){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] %= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_XOR_IMM:
        rt->reg[rt->prog_cntr->dst] ^= rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_XOR_REG:
        rt->reg[rt->prog_cntr->dst] ^= rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_MOV_IMM:
        rt->reg[rt->prog_cntr->dst] = rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_MOV_REG:
        rt->reg[rt->prog_cntr->dst] = rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_ARSH_IMM:
        rt->reg[rt->prog_cntr->dst] = (int32_t)(rt->reg[rt->prog_cntr->dst]) >> rt->prog_cntr->imm;
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;
      case OP_ARSH_REG:
        rt->reg[rt->prog_cntr->dst] = (int32_t)(rt->reg[rt->prog_cntr->dst]) >> rt->reg[rt->prog_cntr->src];
        rt->reg[rt->prog_cntr->dst] &= BIT_32;
        break;


      case OP_LE:
        if (rt->prog_cntr->imm == 16)
          rt->reg[rt->prog_cntr->dst] = htole16(rt->reg[rt->prog_cntr->dst]);
        else if (rt->prog_cntr->imm == 32)
          rt->reg[rt->prog_cntr->dst] = htole32(rt->reg[rt->prog_cntr->dst]);
        else if (rt->prog_cntr->imm == 64)
          rt->reg[rt->prog_cntr->dst] = htole64(rt->reg[rt->prog_cntr->dst]);
        break;
      case OP_BE:
        if (rt->prog_cntr->imm == 16)
          rt->reg[rt->prog_cntr->dst] = htobe16(rt->reg[rt->prog_cntr->dst]);
        else if (rt->prog_cntr->imm == 32)
          rt->reg[rt->prog_cntr->dst] = htobe32(rt->reg[rt->prog_cntr->dst]);
        else if (rt->prog_cntr->imm == 64)
          rt->reg[rt->prog_cntr->dst] = htobe64(rt->reg[rt->prog_cntr->dst]);
        break;


      case OP_ADD64_IMM:
        rt->reg[rt->prog_cntr->dst] += rt->prog_cntr->imm;
        break;
      case OP_ADD64_REG:
        rt->reg[rt->prog_cntr->dst] += rt->reg[rt->prog_cntr->src];
        break;
      case OP_SUB64_IMM:
        rt->reg[rt->prog_cntr->dst] -= rt->prog_cntr->imm;
        break;
      case OP_SUB64_REG:
        rt->reg[rt->prog_cntr->dst] -= rt->reg[rt->prog_cntr->src];
        break;

      case OP_MUL64_IMM:
        rt->reg[rt->prog_cntr->dst] *= rt->prog_cntr->imm;
        break;
      case OP_MUL64_REG:
        rt->reg[rt->prog_cntr->dst] *= rt->reg[rt->prog_cntr->src];
        break;
      case OP_DIV64_IMM:
        if (!rt->prog_cntr->imm){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] /= rt->prog_cntr->imm;
        break;
      case OP_DIV64_REG:
        if (!rt->prog_cntr->src){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] /= rt->reg[rt->prog_cntr->src];
        break;
      case OP_OR64_IMM:
        rt->reg[rt->prog_cntr->dst] |= rt->prog_cntr->imm;
        break;
      case OP_OR64_REG:
        rt->reg[rt->prog_cntr->dst] |= rt->reg[rt->prog_cntr->src];
        break;
      case OP_AND64_IMM:
        rt->reg[rt->prog_cntr->dst] &= rt->prog_cntr->imm;
        break;
      case OP_AND64_REG:
        rt->reg[rt->prog_cntr->dst] &= rt->reg[rt->prog_cntr->src];
        break;
      case OP_LSH64_IMM:
        rt->reg[rt->prog_cntr->dst] <<= rt->prog_cntr->imm;
        break;
      case OP_LSH64_REG:
        rt->reg[rt->prog_cntr->dst] <<= rt->reg[rt->prog_cntr->src];
        break;
      case OP_RSH64_IMM:
        rt->reg[rt->prog_cntr->dst] = (uint64_t)(rt->reg[rt->prog_cntr->dst]) >> rt->prog_cntr->imm;
        break;
      case OP_RSH64_REG:
        rt->reg[rt->prog_cntr->dst] = (uint64_t)(rt->reg[rt->prog_cntr->dst]) >> rt->reg[rt->prog_cntr->src];
        break;
      case OP_NEG64:
        rt->reg[rt->prog_cntr->dst] = -rt->reg[rt->prog_cntr->dst];
        break;
      case OP_MOD64_IMM:
        if (!rt->prog_cntr->imm){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] %= rt->prog_cntr->imm;
        break;
      case OP_MOD64_REG:
        if (!rt->prog_cntr->src){
          printf("Divided by zero error\n");
          abort();
        }
        rt->reg[rt->prog_cntr->dst] %= rt->reg[rt->prog_cntr->src];
        break;
      case OP_XOR64_IMM:
        rt->reg[rt->prog_cntr->dst] ^= rt->prog_cntr->imm;
        break;
      case OP_XOR64_REG:
        rt->reg[rt->prog_cntr->dst] ^= rt->reg[rt->prog_cntr->src];
        break;
      case OP_MOV64_IMM:
        rt->reg[rt->prog_cntr->dst] = rt->prog_cntr->imm;
        break;
      case OP_MOV64_REG:
        rt->reg[rt->prog_cntr->dst] = rt->reg[rt->prog_cntr->src];
        break;
      case OP_ARSH64_IMM:
        rt->reg[rt->prog_cntr->dst] = (int64_t)(rt->reg[rt->prog_cntr->dst]) >> rt->prog_cntr->imm;
        break;
      case OP_ARSH64_REG:
        rt->reg[rt->prog_cntr->dst] = (int64_t)(rt->reg[rt->prog_cntr->dst]) >> rt->reg[rt->prog_cntr->src];
        break;

      case OP_LDXW:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset), sizeof(uint32_t));
        rt->reg[rt->prog_cntr->dst] = *(uint32_t *)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset);
        break;
      case OP_LDXH:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset), sizeof(uint16_t));
        rt->reg[rt->prog_cntr->dst] = *(uint16_t *)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset);
        break;
      case OP_LDXB:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset), sizeof(uint8_t));
        rt->reg[rt->prog_cntr->dst] = *(uint8_t *)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset);
        break;
      case OP_LDXDW:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset), sizeof(uint64_t));
        rt->reg[rt->prog_cntr->dst] = *(uint64_t *)(rt->reg[rt->prog_cntr->src] + rt->prog_cntr->offset);
        break;

      case OP_STW:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint32_t));
        *(uint32_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->prog_cntr->imm;
        break;
      case OP_STH:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint16_t));
        *(uint16_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->prog_cntr->imm;
        break;
      case OP_STB:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint8_t));
        *(uint8_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->prog_cntr->imm;
        break;
      case OP_STDW:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint64_t));
        *(uint64_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->prog_cntr->imm;
        break;

      case OP_STXW:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint32_t));
        *(uint32_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->reg[rt->prog_cntr->src];
        break;
      case OP_STXH:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint16_t));
        *(uint16_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->reg[rt->prog_cntr->src];
        break;
      case OP_STXB:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint8_t));
        *(uint8_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->reg[rt->prog_cntr->src];
        break;
      case OP_STXDW:
        mem_check(rt, (char*)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset), sizeof(uint64_t));
        *(uint64_t *)(rt->reg[rt->prog_cntr->dst] + rt->prog_cntr->offset) = rt->reg[rt->prog_cntr->src];
        break;

      case OP_JA:
            rt->prog_cntr += rt->prog_cntr->offset;
            break;
      case OP_JEQ_IMM:
        if (rt->reg[rt->prog_cntr->dst] == rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JEQ_REG:
        if (rt->reg[rt->prog_cntr->dst] == rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JGT_IMM:
        if (rt->reg[rt->prog_cntr->dst] > (uint32_t)rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JGT_REG:
        if (rt->reg[rt->prog_cntr->dst] > rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JGE_IMM:
        if (rt->reg[rt->prog_cntr->dst] >= (uint32_t)rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JGE_REG:
        if (rt->reg[rt->prog_cntr->dst] >= rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JSET_IMM:
        if (rt->reg[rt->prog_cntr->dst] & rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JSET_REG:
        if (rt->reg[rt->prog_cntr->dst] & rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JNE_IMM:
        if (rt->reg[rt->prog_cntr->dst] != rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JNE_REG:
        if (rt->reg[rt->prog_cntr->dst] != rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JSGT_IMM:
        if ((int64_t)rt->reg[rt->prog_cntr->dst] > rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JSGT_REG:
        if ((int64_t)rt->reg[rt->prog_cntr->dst] > (int64_t)rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JSGE_IMM:
        if ((int64_t)rt->reg[rt->prog_cntr->dst] >= rt->prog_cntr->imm)
            rt->prog_cntr += rt->prog_cntr->offset;
        break;
      case OP_JSGE_REG:
        if ((int64_t)rt->reg[rt->prog_cntr->dst] >= (int64_t)rt->reg[rt->prog_cntr->src])
            rt->prog_cntr += rt->prog_cntr->offset;
        break;

      case OP_LDDW:
        rt->reg[rt->prog_cntr->dst] = (uint32_t)rt->prog_cntr->imm | ((uint64_t)(rt->prog_cntr++)->imm << 32);
        break;

      case OP_EXIT:
        if ((ret_addr = pop_prog_stack(&(rt->prog_stack), &rt->curr_stack)) != 0xFFFFFFFF){
          rt->prog_cntr = rt->code + ret_addr;
          break;
        }
        else
          return rt->reg[0];

      case OP_CALL:
        lookup_relocation(&(rt->relocation_table), (rt->prog_cntr - rt->code)*8, symbol_name);
        if (symbol_name[0] == '\0'){
          printf("Symbol missing");
          abort();
        }
        int64_t next_inst_offset = lookup_symbol(&(rt->symbol_table), symbol_name);
        if (next_inst_offset == -1){
          printf("Symbol missing");
          abort();
        }
        rt->curr_stack = push_prog_stack(&(rt->prog_stack), (rt->prog_cntr - rt->code), rt->curr_stack);
        rt->prog_cntr = rt->code + next_inst_offset/8;
        continue;

      default:
        printf("Unknow instruction\n");
        printf("%01x %01x %01x %02x %04x\n", rt->prog_cntr->opcode,
          rt->prog_cntr->dst, rt->prog_cntr->src, rt->prog_cntr->offset,
          rt->prog_cntr->imm);
        abort();
        break;
    }
    rt->prog_cntr++;
  }
  return -1;
}

uint8_t* push_prog_stack(prog_stack_t* self, uint64_t offset, uint8_t* curr_stack){
  if (self->curr_size < MAX_STACK_SIZE){
    uint8_t * new_stack = (uint8_t*)(malloc(sizeof(uint8_t) * MAX_STACK_SPACE) + MAX_STACK_SPACE);
    if (!new_stack){
      printf("Program stack allocation error\n");
      abort();
    }
    self->offset[self->curr_size] = offset;
    self->stack_base[self->curr_size] = curr_stack;
    self->curr_size++;
    return new_stack;
  }
  else{
    printf("Return address stack overflow\n");
    abort();
  }
  return NULL;
}

uint64_t pop_prog_stack(prog_stack_t* self, uint8_t** curr_stack){
  if (*curr_stack)
    free(*curr_stack - MAX_STACK_SPACE);
  if (self->curr_size > 0){
    self->curr_size--;
    *curr_stack = self->stack_base[self->curr_size];
    return self->offset[self->curr_size];
  }
  else{
    *curr_stack = NULL;
    return 0xFFFFFFFF;
  }
}

void cleanup(runtime_t * runtime){
  if (runtime->code) free(runtime->code);
  if (runtime->mem) free(runtime->mem);
  destroy_table_symbol(&(runtime->symbol_table));
  destroy_table_relocation(&(runtime->relocation_table));
}
