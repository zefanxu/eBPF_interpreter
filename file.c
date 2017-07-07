#include <string.h>
#include "ebpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <assert.h>

void create_table_relocation(relocation_table_t* self, size_t t_size){
  self->table_cap = t_size;
  self->table_size = 0;
  self->entry = (relocation_table_entry_t*)
    malloc(sizeof(relocation_table_entry_t) * self->table_cap);
}
void destroy_table_relocation(relocation_table_t* self){
  if (self->entry) free(self->entry);
}
void add_entry_relocation(relocation_table_t* self, const char* sym_name, int64_t offset){
  assert(self->table_size < self->table_cap);
  strcpy(self->entry[self->table_size].sym_name, sym_name);
  self->entry[self->table_size].offset = offset;
  self->table_size++;
}
void lookup_relocation(relocation_table_t* self, int64_t offset, char* ret_symbol_name){
  int i;
  for (i = 0; i < self->table_size; i++){
    if (self->entry[i].offset == offset){
      strcpy(ret_symbol_name, self->entry[i].sym_name);
      return;
    }
  }
  ret_symbol_name[0] = '\0';
}

void create_table_symbol(symbol_table_t* self, size_t t_size){
  self->table_cap = t_size;
  self->table_size = 0;
  self->entry = (symbol_table_entry_t*)
    malloc(sizeof(symbol_table_entry_t) * self->table_cap);
}
void destroy_table_symbol(symbol_table_t* self){
  if (self->entry) free(self->entry);
}
void add_entry_symbol(symbol_table_t* self, const char* sym_name, int64_t offset){
  assert(self->table_size < self->table_cap);
  strcpy(self->entry[self->table_size].sym_name, sym_name);
  self->entry[self->table_size].offset = offset;
  self->table_size++;
}
int64_t lookup_symbol(symbol_table_t* self, const char* sym_name){
  int i;
  for (i = 0; i < self->table_size; i++){
    if (!strcmp(self->entry[i].sym_name, sym_name))
      return self->entry[i].offset;
  }
  return -1;
}

void load_elf_file(runtime_t* runtime, const char* fname){
  assert(runtime);
  assert(fname);
  FILE * fp = fopen(fname, "r");
  if (!fp){
    printf("Can't open the file\n");
    abort();
  }
  fseek(fp, 0L, SEEK_END);
  long long file_len = ftell(fp);
  if (file_len > MAX_FILE_SIZE || file_len < 0){
    printf("File size error\n");
    abort();
  }
  char* file_buffer = (char*)malloc(sizeof(char) * (file_len));
  if (!file_buffer){
    printf("Malloc error\n");
    abort();
  }
  if (fseek(fp, 0L, SEEK_SET) != 0) {
    printf("File error\n");
    abort();
  }
  size_t read_len = fread(file_buffer, sizeof(char), file_len, fp);
  if (ferror(fp) != 0) {
    printf("File read error\n");
    abort();
  }
  parse_elf_file(runtime, file_buffer, read_len);
  free(file_buffer);
}

static const void *
bounds_check(struct bounds *bounds, uint64_t offset, uint64_t size)
{
  if (offset + size > bounds->size || offset + size < offset) {
      return NULL;
  }
  return bounds->base + offset;
}


void parse_elf_file(runtime_t * runtime, char* file_buffer, size_t file_len){
  struct bounds b = { .base=file_buffer, .size=file_len };
  void *text_copy = NULL;
  int i;
  const Elf64_Ehdr *ehdr = bounds_check(&b, 0, sizeof(*ehdr));
  if (!ehdr) {
      printf("not enough data for ELF header");
      goto error;
  }
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
      printf("wrong magic");
      goto error;
  }
  if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
      printf("wrong class");
      goto error;
  }
  if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
      printf("wrong byte order");
      goto error;
  }
  if (ehdr->e_ident[EI_VERSION] != 1) {
      printf("wrong version");
      goto error;
  }
  if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
      printf("wrong OS ABI");
      goto error;
  }
  if (ehdr->e_type != ET_REL) {
      printf("wrong type, expected relocatable");
      goto error;
  }
  if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
      printf("wrong machine, expected none or BPF, got %d",
                           ehdr->e_machine);
      goto error;
  }
  if (ehdr->e_shnum > MAX_SECTIONS) {
      printf("too many sections");
      goto error;
  }
  /* Parse section headers into an array */
  struct section sections[MAX_SECTIONS];
  for (i = 0; i < ehdr->e_shnum; i++) {
      const Elf64_Shdr *shdr = bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
      if (!shdr) {
          printf("bad section header offset or size");
          goto error;
      }
      const void *data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
      if (!data) {
          printf("bad section offset or size");
          goto error;
      }
      sections[i].shdr = shdr;
      sections[i].data = data;
      sections[i].size = shdr->sh_size;
  }
  /* Find first text section */
  int text_shndx = 0;
  for (i = 0; i < ehdr->e_shnum; i++) {
      const Elf64_Shdr *shdr = sections[i].shdr;
      if (shdr->sh_type == SHT_PROGBITS &&
              shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
          text_shndx = i;
          break;
      }
  }
  if (!text_shndx) {
      printf("text section not found");
      goto error;
  }
  struct section *text = &sections[text_shndx];
  /* May need to modify text for relocations, so make a copy */
  text_copy = malloc(text->size);
  if (!text_copy) {
      printf("failed to allocate memory");
      goto error;
  }
  memcpy(text_copy, text->data, text->size);
  /* Process each relocation section */
  for (i = 0; i < ehdr->e_shnum; i++) {
      struct section *rel = &sections[i];
      if (rel->shdr->sh_type != SHT_REL) {
          continue;
      } else if (rel->shdr->sh_info != text_shndx) {
          continue;
      }
      const Elf64_Rel *rs = rel->data;
      if (rel->shdr->sh_link >= ehdr->e_shnum) {
          printf("bad symbol table section index");
          goto error;
      }
      struct section *symtab = &sections[rel->shdr->sh_link];
      const Elf64_Sym *syms = symtab->data;
      uint32_t num_syms = symtab->size/sizeof(syms[0]);
      struct section *strtab = &sections[symtab->shdr->sh_link];
      const char *strings = strtab->data;

      int q;
      create_table_symbol(&(runtime->symbol_table), num_syms);
      if (DEBUG)
        printf("SYMBOL TABLE:\n");
      for (q = 0; q < num_syms; q++){
        const Elf64_Sym * curr_sym = &syms[q];
        const char *sym_name = strings + curr_sym->st_name;
        if (DEBUG)
          printf("%s: %lx\n", sym_name, curr_sym->st_value);
        add_entry_symbol(&(runtime->symbol_table), sym_name, curr_sym->st_value);
      }

      if (symtab->shdr->sh_link >= ehdr->e_shnum) {
          printf("bad string table section index");
          goto error;
      }
      int j;
      if (DEBUG) printf("RELOCATION TABLE\n");
      create_table_relocation(&(runtime->relocation_table), rel->size/sizeof(Elf64_Rel));
      for (j = 0; j < rel->size/sizeof(Elf64_Rel); j++) {
          const Elf64_Rel *r = &rs[j];
          if (ELF64_R_TYPE(r->r_info) != 2) {
              printf("bad relocation type %lu", ELF64_R_TYPE(r->r_info));
              goto error;
          }
          uint32_t sym_idx = ELF64_R_SYM(r->r_info);
          if (sym_idx >= num_syms) {
              printf("bad symbol index");
              goto error;
          }
          const Elf64_Sym *sym = &syms[sym_idx];
          if (sym->st_name >= strtab->size) {
              printf("bad symbol name");
              goto error;
          }
          const char *sym_name = strings + sym->st_name;
          if (r->r_offset + 8 > text->size) {
              printf("bad relocation offset");
              goto error;
          }
          if(DEBUG)
            printf("offset:%lx, symbol:%s\n", r->r_offset, sym_name);
          add_entry_relocation(&(runtime->relocation_table), sym_name, r->r_offset);

      }
  }
  parse_bin_file(runtime, text_copy, sections[text_shndx].size);
  free(text_copy);
  return;
  error:
  free(text_copy);
  abort();
}

void load_bin_file(runtime_t* runtime, const char* fname){
  assert(runtime);
  assert(fname);
  FILE * fp = fopen(fname, "r");
  if (!fp){
    printf("Can't open the file\n");
    abort();
  }
  fseek(fp, 0L, SEEK_END);
  long long file_len = ftell(fp);
  if (file_len > MAX_FILE_SIZE || file_len < 0){
    printf("File size error\n");
    abort();
  }
  char* file_buffer = (char*)malloc(sizeof(char) * (file_len));
  if (!file_buffer){
    printf("Malloc error\n");
    abort();
  }
  if (fseek(fp, 0L, SEEK_SET) != 0) {
    printf("File error\n");
    abort();
  }
  size_t read_len = fread(file_buffer, sizeof(char), file_len, fp);
  if (ferror(fp) != 0) {
    printf("File read error\n");
    abort();
  }
  parse_bin_file(runtime, file_buffer, read_len);
  free(file_buffer);
}

void parse_bin_file(runtime_t * runtime, char * file, size_t file_len){
  size_t instruction_cap = 100; //magic number for # of instructions can be loaded
  size_t instruction_loaded = 0;
  instruction_t * instruction_set = (instruction_t*) malloc(sizeof(instruction_t) * instruction_cap);
  if (!instruction_set){
    printf("Malloc error\n");
    abort();
  }
  char * curr_read_pos = file;
  if (DEBUG) printf("Program Loaded:\n");
  while (curr_read_pos < (file + file_len)){
    if (instruction_loaded >= instruction_cap){
      instruction_cap += 100;
      instruction_set = (instruction_t*) realloc(instruction_set ,sizeof(instruction_t) * instruction_cap);
      if (!instruction_set){
        printf("Realloc error\n");
        abort();
      }
    }
    instruction_set[instruction_loaded++] = *((instruction_t*)(curr_read_pos));
    if (DEBUG){
      instruction_t curr_instruction = instruction_set[instruction_loaded-1];
      printf("%04lx: %02x %01x %01x %04hx %08x\n", instruction_loaded-1, curr_instruction.opcode,
        curr_instruction.dst, curr_instruction.src, curr_instruction.offset,
        curr_instruction.imm);
    }
    curr_read_pos += 8; //64 bit instruction size
  }
  instruction_set = (instruction_t*) realloc(instruction_set ,sizeof(instruction_t) * instruction_loaded);
  if (!instruction_set){
    printf("Realloc error\n");
    abort();
  }
  runtime->code = instruction_set;
  runtime->instruction_size = instruction_loaded;
  runtime->prog_cntr = runtime->code;
}

void load_mem_file(runtime_t * runtime, const char* fname){
  assert(runtime);
  assert(fname);
  FILE * fp = fopen(fname, "r");
  if (!fp){
    printf("Can't open the file\n");
    abort();
  }
  fseek(fp, 0L, SEEK_END);
  long long file_len = ftell(fp);
  if (file_len > MAX_FILE_SIZE || file_len < 0){
    printf("File size error\n");
    abort();
  }
  char* file_buffer = (char*)calloc(MAX_MEM_SIZE, sizeof(char));
  if (!file_buffer){
    printf("Malloc error\n");
    abort();
  }
  if (fseek(fp, 0L, SEEK_SET) != 0) {
    printf("File error\n");
    abort();
  }
  size_t read_len = fread(file_buffer, sizeof(char), file_len, fp);
  if (ferror(fp) != 0) {
    printf("File read error\n");
    abort();
  }
  runtime->mem = (uint8_t*)file_buffer;
  if (DEBUG){
    unsigned int i = 0;
    printf("Memory Loaded:\n");
    for (i = 0; i < file_len; i+= 4)
      printf("%p: %02x %02x %02x %02x\n", runtime->mem,
        *(runtime->mem+i), *(runtime->mem+i+1),
        *(runtime->mem+i+2), *(runtime->mem+i+3));
  }
}
