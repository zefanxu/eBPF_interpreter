#ifndef JIT_H
#define JIT_H
#include "ebpf.h"

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8  8
#define R9  9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

typedef struct jit_runtime_t{
  runtime_t itprtr_rt;
}jit_runtime_t;

#endif
