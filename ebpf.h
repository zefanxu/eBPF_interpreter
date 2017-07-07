#ifndef EBPF_H
#define EBPF_H
#include <stdint.h>
#include <stdlib.h>
#include <elf.h>
#include <assert.h>
#include <string.h>

#define DEBUG 1
#define MAX_STACK_SIZE 1024
#define MAX_STACK_SPACE 1024
#define MAX_FILE_SIZE 1024*1024
#define MAX_MEM_SIZE 1024*1024
#define REG_SIZE 16
#define BIT_32 0x0000FFFF
#define MAX_SYMBOL_NAME_LEN 128
#define MAX_SECTIONS 32
#define EM_BPF 247

typedef struct __attribute__((__packed__)) instruction_t {
  uint8_t opcode;
  uint8_t dst : 4;
  uint8_t src : 4;
  int16_t offset;
  int32_t imm;
} instruction_t;

typedef struct symbol_table_entry_t{
  char sym_name[MAX_SYMBOL_NAME_LEN];
  int64_t offset;
}symbol_table_entry_t;

//symbol name -> symbol offset
typedef struct symbol_table_t {
  size_t table_cap;
  size_t table_size;
  symbol_table_entry_t * entry;
}symbol_table_t;



typedef struct relocation_table_entry_t{
  char sym_name[MAX_SYMBOL_NAME_LEN];
  int64_t offset;
}relocation_table_entry_t;

//call instruction offset -> symbol name
typedef struct relocation_table_t{
  size_t table_cap;
  size_t table_size;
  relocation_table_entry_t * entry;
}relocation_table_t;

typedef struct prog_stack_t{
  uint64_t offset[MAX_STACK_SIZE];
  uint8_t* stack_base[MAX_STACK_SIZE];
  size_t curr_size;
}prog_stack_t;

typedef struct runtime_t{
  instruction_t * code;
  instruction_t * prog_cntr;
  uint8_t * mem;
  uint8_t * curr_stack;

  symbol_table_t symbol_table;
  relocation_table_t relocation_table;
  prog_stack_t prog_stack;

  uint64_t reg[REG_SIZE];
  size_t instruction_size;
}runtime_t;


struct bounds {
    const void *base;
    uint64_t size;
};

struct section {
    const Elf64_Shdr *shdr;
    const void *data;
    uint64_t size;
};


//relocation/symbol table functions
void create_table_relocation(relocation_table_t* self, size_t t_size);
void destroy_table_relocation(relocation_table_t* self);
void add_entry_relocation(relocation_table_t* self, const char* sym_name, int64_t offset);
void lookup_relocation(relocation_table_t* self, int64_t offset, char* ret_symbol_name);
void create_table_symbol(symbol_table_t* self, size_t t_size);
void destroy_table_symbol(symbol_table_t* self);
void add_entry_symbol(symbol_table_t* self, const char* sym_name, int64_t offset);
int64_t lookup_symbol(symbol_table_t* self, const char* sym_name);

//ret addr stack management functions
uint8_t* push_prog_stack(prog_stack_t* self, uint64_t offset, uint8_t* curr_stack);
uint64_t pop_prog_stack(prog_stack_t* self, uint8_t** curr_stack);

//file loading functions
void load_bin_file(runtime_t* runtime, const char* fname);
void parse_bin_file(runtime_t * runtime, char * file, size_t file_len);
void load_mem_file(runtime_t* runtime, const char* fname);
void parse_elf_file(runtime_t * runtime, char* file_buffer, size_t file_len);
void load_elf_file(runtime_t* runtime, const char* fname);


void setup(runtime_t * runtime, const char* entry_function);
uint64_t execution(runtime_t * rt, const char* entry_function);
void cleanup(runtime_t * runtime);

//eBPF opcode
//https://github.com/iovisor/bpf-docs

#define CLS_MASK 0x07
#define ALU_OP_MASK 0xf0

#define CLS_LD 0x00
#define CLS_LDX 0x01
#define CLS_ST 0x02
#define CLS_STX 0x03
#define CLS_ALU 0x04
#define CLS_JMP 0x05
#define CLS_ALU64 0x07

#define SRC_IMM 0x00
#define SRC_REG 0x08

#define SIZE_W 0x00
#define SIZE_H 0x08
#define SIZE_B 0x10
#define SIZE_DW 0x18

#define MODE_IMM 0x00
#define MODE_MEM 0x60

#define OP_ADD_IMM  (CLS_ALU|SRC_IMM|0x00)
#define OP_ADD_REG  (CLS_ALU|SRC_REG|0x00)
#define OP_SUB_IMM  (CLS_ALU|SRC_IMM|0x10)
#define OP_SUB_REG  (CLS_ALU|SRC_REG|0x10)
#define OP_MUL_IMM  (CLS_ALU|SRC_IMM|0x20)
#define OP_MUL_REG  (CLS_ALU|SRC_REG|0x20)
#define OP_DIV_IMM  (CLS_ALU|SRC_IMM|0x30)
#define OP_DIV_REG  (CLS_ALU|SRC_REG|0x30)
#define OP_OR_IMM   (CLS_ALU|SRC_IMM|0x40)
#define OP_OR_REG   (CLS_ALU|SRC_REG|0x40)
#define OP_AND_IMM  (CLS_ALU|SRC_IMM|0x50)
#define OP_AND_REG  (CLS_ALU|SRC_REG|0x50)
#define OP_LSH_IMM  (CLS_ALU|SRC_IMM|0x60)
#define OP_LSH_REG  (CLS_ALU|SRC_REG|0x60)
#define OP_RSH_IMM  (CLS_ALU|SRC_IMM|0x70)
#define OP_RSH_REG  (CLS_ALU|SRC_REG|0x70)
#define OP_NEG      (CLS_ALU|0x80)
#define OP_MOD_IMM  (CLS_ALU|SRC_IMM|0x90)
#define OP_MOD_REG  (CLS_ALU|SRC_REG|0x90)
#define OP_XOR_IMM  (CLS_ALU|SRC_IMM|0xa0)
#define OP_XOR_REG  (CLS_ALU|SRC_REG|0xa0)
#define OP_MOV_IMM  (CLS_ALU|SRC_IMM|0xb0)
#define OP_MOV_REG  (CLS_ALU|SRC_REG|0xb0)
#define OP_ARSH_IMM (CLS_ALU|SRC_IMM|0xc0)
#define OP_ARSH_REG (CLS_ALU|SRC_REG|0xc0)
#define OP_LE       (CLS_ALU|SRC_IMM|0xd0)
#define OP_BE       (CLS_ALU|SRC_REG|0xd0)

#define OP_ADD64_IMM  (CLS_ALU64|SRC_IMM|0x00)
#define OP_ADD64_REG  (CLS_ALU64|SRC_REG|0x00)
#define OP_SUB64_IMM  (CLS_ALU64|SRC_IMM|0x10)
#define OP_SUB64_REG  (CLS_ALU64|SRC_REG|0x10)
#define OP_MUL64_IMM  (CLS_ALU64|SRC_IMM|0x20)
#define OP_MUL64_REG  (CLS_ALU64|SRC_REG|0x20)
#define OP_DIV64_IMM  (CLS_ALU64|SRC_IMM|0x30)
#define OP_DIV64_REG  (CLS_ALU64|SRC_REG|0x30)
#define OP_OR64_IMM   (CLS_ALU64|SRC_IMM|0x40)
#define OP_OR64_REG   (CLS_ALU64|SRC_REG|0x40)
#define OP_AND64_IMM  (CLS_ALU64|SRC_IMM|0x50)
#define OP_AND64_REG  (CLS_ALU64|SRC_REG|0x50)
#define OP_LSH64_IMM  (CLS_ALU64|SRC_IMM|0x60)
#define OP_LSH64_REG  (CLS_ALU64|SRC_REG|0x60)
#define OP_RSH64_IMM  (CLS_ALU64|SRC_IMM|0x70)
#define OP_RSH64_REG  (CLS_ALU64|SRC_REG|0x70)
#define OP_NEG64      (CLS_ALU64|0x80)
#define OP_MOD64_IMM  (CLS_ALU64|SRC_IMM|0x90)
#define OP_MOD64_REG  (CLS_ALU64|SRC_REG|0x90)
#define OP_XOR64_IMM  (CLS_ALU64|SRC_IMM|0xa0)
#define OP_XOR64_REG  (CLS_ALU64|SRC_REG|0xa0)
#define OP_MOV64_IMM  (CLS_ALU64|SRC_IMM|0xb0)
#define OP_MOV64_REG  (CLS_ALU64|SRC_REG|0xb0)
#define OP_ARSH64_IMM (CLS_ALU64|SRC_IMM|0xc0)
#define OP_ARSH64_REG (CLS_ALU64|SRC_REG|0xc0)

#define OP_LDXW  (CLS_LDX|MODE_MEM|SIZE_W)
#define OP_LDXH  (CLS_LDX|MODE_MEM|SIZE_H)
#define OP_LDXB  (CLS_LDX|MODE_MEM|SIZE_B)
#define OP_LDXDW (CLS_LDX|MODE_MEM|SIZE_DW)
#define OP_STW   (CLS_ST|MODE_MEM|SIZE_W)
#define OP_STH   (CLS_ST|MODE_MEM|SIZE_H)
#define OP_STB   (CLS_ST|MODE_MEM|SIZE_B)
#define OP_STDW  (CLS_ST|MODE_MEM|SIZE_DW)
#define OP_STXW  (CLS_STX|MODE_MEM|SIZE_W)
#define OP_STXH  (CLS_STX|MODE_MEM|SIZE_H)
#define OP_STXB  (CLS_STX|MODE_MEM|SIZE_B)
#define OP_STXDW (CLS_STX|MODE_MEM|SIZE_DW)
#define OP_LDDW  (CLS_LD|MODE_IMM|SIZE_DW)

#define OP_JA       (CLS_JMP|0x00)
#define OP_JEQ_IMM  (CLS_JMP|SRC_IMM|0x10)
#define OP_JEQ_REG  (CLS_JMP|SRC_REG|0x10)
#define OP_JGT_IMM  (CLS_JMP|SRC_IMM|0x20)
#define OP_JGT_REG  (CLS_JMP|SRC_REG|0x20)
#define OP_JGE_IMM  (CLS_JMP|SRC_IMM|0x30)
#define OP_JGE_REG  (CLS_JMP|SRC_REG|0x30)
#define OP_JSET_REG (CLS_JMP|SRC_REG|0x40)
#define OP_JSET_IMM (CLS_JMP|SRC_IMM|0x40)
#define OP_JNE_IMM  (CLS_JMP|SRC_IMM|0x50)
#define OP_JNE_REG  (CLS_JMP|SRC_REG|0x50)
#define OP_JSGT_IMM (CLS_JMP|SRC_IMM|0x60)
#define OP_JSGT_REG (CLS_JMP|SRC_REG|0x60)
#define OP_JSGE_IMM (CLS_JMP|SRC_IMM|0x70)
#define OP_JSGE_REG (CLS_JMP|SRC_REG|0x70)
#define OP_CALL     (CLS_JMP|0x80)
#define OP_EXIT     (CLS_JMP|0x90)

#endif
