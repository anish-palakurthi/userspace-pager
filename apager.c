#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    void* entry_point;
    void* prog_stack;
    size_t stack_size;
    char** argv;
    int argc;
    char** envp;
} program_info_t;

static void validate_elf(Elf64_Ehdr* ehdr) {
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        exit(1);
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Not a 64-bit ELF\n");
        exit(1);
    }
    if (ehdr->e_type != ET_EXEC) {
        fprintf(stderr, "Not an executable\n");
        exit(1);
    }
}

static void map_program_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        // Calculate page-aligned addresses
        size_t page_size = sysconf(_SC_PAGESIZE);
        void* page_addr = (void*)(phdr[i].p_vaddr & ~(page_size - 1));
        size_t page_offset = phdr[i].p_vaddr & (page_size - 1);
        size_t mapping_size = phdr[i].p_memsz + page_offset;

        // Map segment
        void* addr = mmap(
            page_addr,
            mapping_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_FIXED,
            fd,
            phdr[i].p_offset - page_offset
        );

        if (addr == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }

        fprintf(stderr, "Mapped segment at %p, offset %lu, size %zu\n", 
                addr, phdr[i].p_offset - page_offset, mapping_size);
    }
}

static void setup_stack(program_info_t* info) {
    // Allocate new stack
    void* stack = mmap(
        NULL,
        info->stack_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
        -1,
        0
    );

    if (stack == MAP_FAILED) {
        perror("mmap stack");
        exit(1);
    }

    // Stack grows down - start at the top
    char** stack_ptr = (char**)(stack + info->stack_size);

    // Push args onto stack from top down
    
    // First, copy arguments
    int envc = 0;
    for (char** env = info->envp; *env != NULL; env++) {
        envc++;
    }

    // Push auxiliary vector (null for now)
    stack_ptr--;
    *stack_ptr = NULL;
    stack_ptr--;
    *stack_ptr = NULL;

    // Push environment pointers
    for (int i = envc; i >= 0; i--) {
        stack_ptr--;
        *stack_ptr = info->envp[i];
    }

    // Push argument pointers
    for (int i = info->argc; i >= 0; i--) {
        stack_ptr--;
        *stack_ptr = (i == info->argc) ? NULL : info->argv[i];
    }

    // Push argc
    stack_ptr--;
    *(int*)stack_ptr = info->argc;

    info->prog_stack = stack_ptr;
    fprintf(stderr, "Stack allocated at %p, stack pointer at %p\n", stack, stack_ptr);
}

static void transfer_control(program_info_t* info) {
    // According to System V AMD64 ABI:
    // rdi = argc
    // rsi = argv
    // rdx = envp
    register unsigned long stack asm("rsp") = (unsigned long)info->prog_stack;
    register int argc asm("rdi") = info->argc;
    register char** argv asm("rsi") = (char**)((char*)info->prog_stack + 8);
    register char** envp asm("rdx") = argv + info->argc + 1;
    register unsigned long entry asm("r11") = (unsigned long)info->entry_point;

    fprintf(stderr, "Transferring control: entry=%p, stack=%p, argc=%d\n", 
            info->entry_point, (void*)stack, argc);

    asm volatile(
        // Zero general purpose registers
        "xor %%rax, %%rax\n"
        "xor %%rbx, %%rbx\n"
        "xor %%rcx, %%rcx\n"
        "xor %%r8, %%r8\n"
        "xor %%r9, %%r9\n"
        "xor %%r10, %%r10\n"
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%r14, %%r14\n"
        "xor %%r15, %%r15\n"
        // "xor %%rbp, %%rbp\n"  // Remove this line
        // Set up stack frame and jump
        "mov %[stack], %%rsp\n"
        "pushq %[entry]\n"
        "ret\n"
        : 
        : [entry] "r" (entry),
        [stack] "r" (stack),
        "D" (argc),    // rdi
        "S" (argv),    // rsi
        "d" (envp)     // rdx
        : "memory", "rax", "rbx", "rcx", "r8", "r9", "r10", 
        "r12", "r13", "r14", "r15" // Remove "rbp" from the clobber list
    );
    __builtin_unreachable();
}

int main(int argc, char** argv, char** envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(1);
    }

    // Open the target program
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    // Read ELF header
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read");
        exit(1);
    }

    // Validate ELF file
    validate_elf(&ehdr);

    // Read program headers
    Elf64_Phdr* phdr = malloc(ehdr.e_phentsize * ehdr.e_phnum);
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
        perror("lseek");
        exit(1);
    }
    if (read(fd, phdr, ehdr.e_phentsize * ehdr.e_phnum) != 
        ehdr.e_phentsize * ehdr.e_phnum) {
        perror("read");
        exit(1);
    }

    // Initialize program info
    program_info_t prog_info = {
        .entry_point = (void*)ehdr.e_entry,
        .stack_size = 8 * 1024 * 1024, // 8MB stack
        .argv = argv + 1,
        .argc = argc - 1,
        .envp = envp
    };

    // Map segments and setup program
    map_program_segments(fd, &ehdr, phdr);
    setup_stack(&prog_info);

    // Transfer control to loaded program
    transfer_control(&prog_info);
}