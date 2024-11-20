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

// Global state for demand paging
typedef struct {
    int fd;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
} program_state_t;

static program_state_t prog_state;
static size_t page_size;

// Structure to hold program info (unchanged)
typedef struct {
    void* entry_point;
    void* prog_stack;
    size_t stack_size;
    char** argv;
    int argc;
    char** envp;
} program_info_t;

// Signal handler for page faults
static void segv_handler(int sig __attribute__((unused)), 
                        siginfo_t* si, 
                        void* unused __attribute__((unused))) {
    void* fault_addr = si->si_addr;
    
    // Rest of handler remains the same

    
    // Find which segment contains fault_addr
    for (int i = 0; i < prog_state.ehdr->e_phnum; i++) {
        Elf64_Phdr* ph = &prog_state.phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        
        void* seg_start = (void*)ph->p_vaddr;
        void* seg_end = seg_start + ph->p_memsz;
        
        if (fault_addr >= seg_start && fault_addr < seg_end) {
            // Calculate page-aligned addresses
            void* page_addr = (void*)((uintptr_t)fault_addr & ~(page_size - 1));
            size_t page_offset = ph->p_offset + 
                ((uintptr_t)fault_addr - (uintptr_t)seg_start);
            page_offset &= ~(page_size - 1);

            // Map just this page
            void* mapped = mmap(
                page_addr,
                page_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_FIXED | MAP_PRIVATE,
                prog_state.fd,
                page_offset
            );
            
            if (mapped == MAP_FAILED) {
                perror("mmap in fault handler");
                exit(1);
            }
            
            fprintf(stderr, "Demand mapped page at %p\n", mapped);
            return;
        }
    }
    
    // If we get here, it's a real segfault
    fprintf(stderr, "Segmentation fault at address %p\n", fault_addr);
    exit(1);
}

// Function prototypes
static void validate_elf(Elf64_Ehdr* ehdr);
static void prepare_program_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr);
static void setup_stack(program_info_t* info);
static void transfer_control(program_info_t* info) __attribute__((noreturn));

int main(int argc, char** argv, char** envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(1);
    }

    page_size = sysconf(_SC_PAGESIZE);

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

    // Set up global state for fault handler
    prog_state.fd = fd;
    prog_state.ehdr = &ehdr;
    prog_state.phdr = phdr;

    // Set up signal handler
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
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

    // Prepare virtual memory regions for segments (but don't map content yet)
    prepare_program_segments(fd, &ehdr, phdr);
    
    // Setup stack
    setup_stack(&prog_info);

    // Transfer control to loaded program
    transfer_control(&prog_info);
}



static void prepare_program_segments(int fd __attribute__((unused)), 
                                   Elf64_Ehdr* ehdr, 
                                   Elf64_Phdr* phdr) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        // Calculate page-aligned addresses
        void* page_addr = (void*)(phdr[i].p_vaddr & ~(page_size - 1));
        size_t page_offset = phdr[i].p_vaddr & (page_size - 1);
        size_t mapping_size = phdr[i].p_memsz + page_offset;

        // Reserve the address space but don't map content
        void* addr = mmap(
            page_addr,
            mapping_size,
            PROT_NONE,  // No permissions - will trigger fault when accessed
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0
        );

        if (addr == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }

        fprintf(stderr, "Reserved segment at %p, size %zu\n", addr, mapping_size);
    }
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
    char** stack_top = (char**)(info->prog_stack + info->stack_size);
    
    // Setup the stack content
    char** stack_ptr = stack_top;

    // Auxiliary vectors (placeholder)
    stack_ptr -= 2;
    stack_ptr[0] = NULL;
    stack_ptr[1] = NULL;

    // Environment variables (placeholder)
    stack_ptr -= 1;
    stack_ptr[0] = NULL;

    // argv
    stack_ptr -= info->argc + 1;
    for (int i = 0; i < info->argc; i++) {
        stack_ptr[i] = info->argv[i];
    }
    stack_ptr[info->argc] = NULL;

    // Save the final stack pointer
    info->prog_stack = stack_ptr;
    
    fprintf(stderr, "Stack allocated at %p\n", stack_ptr);
}

static void transfer_control(program_info_t* info) {
    // Use registers directly
    register unsigned long entry asm("rax") = (unsigned long)info->entry_point;
    register unsigned long stack asm("rsp") = (unsigned long)info->prog_stack;
    
    asm volatile(
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
        "jmp *%%rax\n"
        :
        : "r" (stack), "r" (entry)
        : "memory", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );
    __builtin_unreachable();
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