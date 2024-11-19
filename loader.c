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

// Structure to hold program info
typedef struct {
    void* entry_point;
    void* prog_stack;
    size_t stack_size;
    char** argv;
    int argc;
    char** envp;
} program_info_t;

// Function prototypes
static void validate_elf(Elf64_Ehdr* ehdr);
static void* map_program_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr);
static void setup_stack(program_info_t* info);
static void transfer_control(program_info_t* info) __attribute__((noreturn));

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

    // Map program segments
    void* base = map_program_segments(fd, &ehdr, phdr);
    
    // Setup stack
    setup_stack(&prog_info);

    // Transfer control to loaded program
    transfer_control(&prog_info);
}

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

static void* map_program_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        // Calculate page-aligned addresses
        void* page_addr = (void*)(phdr[i].p_vaddr & ~(sysconf(_SC_PAGESIZE) - 1));
        size_t page_offset = phdr[i].p_vaddr & (sysconf(_SC_PAGESIZE) - 1);
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

        fprintf(stderr, "Mapped segment at %p, size %zu\n", addr, mapping_size);
    }

    return NULL;
}

static void setup_stack(program_info_t* info) {
    // Allocate new stack
    info->prog_stack = mmap(
        NULL,
        info->stack_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
        -1,
        0
    );

    if (info->prog_stack == MAP_FAILED) {
        perror("mmap stack");
        exit(1);
    }

    // Stack grows down - start at the top
    void* stack_top = info->prog_stack + info->stack_size;
    
    // TODO: Set up auxiliary vectors, environment, and argv
    // This is a placeholder - actual implementation needs careful stack setup
    
    fprintf(stderr, "Stack allocated at %p\n", info->prog_stack);
}

static void transfer_control(program_info_t* info) {
    // Zero all registers and jump to entry point
    asm volatile(
        "xor %%rax, %%rax\n"
        "xor %%rbx, %%rbx\n"
        "xor %%rcx, %%rcx\n"
        "xor %%rdx, %%rdx\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rdi, %%rdi\n"
        "xor %%r8, %%r8\n"
        "xor %%r9, %%r9\n"
        "xor %%r10, %%r10\n"
        "xor %%r11, %%r11\n"
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%r14, %%r14\n"
        "xor %%r15, %%r15\n"
        "jmp *%0"
        : : "r"(info->entry_point) : "memory"
    );
    __builtin_unreachable();
}