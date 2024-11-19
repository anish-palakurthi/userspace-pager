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
#include <time.h>

// Global state for demand paging
typedef struct {
    int fd;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    // Statistics
    size_t page_faults;
    size_t pages_mapped;
    struct timespec start_time;
    struct timespec end_time;
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

// Map a single page at specified address
static void* map_single_page(void* addr, off_t offset) {
    void* page_addr = (void*)((uintptr_t)addr & ~(page_size - 1));
    
    void* mapped = mmap(
        page_addr,
        page_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE,
        prog_state.fd,
        offset
    );
    
    if (mapped != MAP_FAILED) {
        prog_state.pages_mapped++;
        fprintf(stderr, "Mapped page at %p from offset %ld\n", mapped, offset);
    }
    
    return mapped;
}

// Predict and map additional pages
static void predict_and_map_pages(void* fault_addr, Elf64_Phdr* ph) {
    void* seg_start = (void*)ph->p_vaddr;
    void* seg_end = seg_start + ph->p_memsz;
    
    // Calculate current page offset
    off_t base_offset = ph->p_offset + 
        ((uintptr_t)fault_addr - (uintptr_t)seg_start);
    base_offset &= ~(page_size - 1);
    
    // Map next sequential page (if within segment)
    void* next_page = (void*)((uintptr_t)fault_addr + page_size);
    if (next_page < seg_end) {
        map_single_page(next_page, base_offset + page_size);
    }
    
    // Map one page further (if within segment)
    // This could use more sophisticated prediction
    void* next_next_page = (void*)((uintptr_t)fault_addr + 2 * page_size);
    if (next_next_page < seg_end) {
        map_single_page(next_next_page, base_offset + 2 * page_size);
    }
}

// Signal handler for page faults
static void segv_handler(int sig, siginfo_t* si, void* unused) {
    void* fault_addr = si->si_addr;
    prog_state.page_faults++;
    
    // Find which segment contains fault_addr
    for (int i = 0; i < prog_state.ehdr->e_phnum; i++) {
        Elf64_Phdr* ph = &prog_state.phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        
        void* seg_start = (void*)ph->p_vaddr;
        void* seg_end = seg_start + ph->p_memsz;
        
        if (fault_addr >= seg_start && fault_addr < seg_end) {
            // Calculate page offset
            off_t page_offset = ph->p_offset + 
                ((uintptr_t)fault_addr - (uintptr_t)seg_start);
            page_offset &= ~(page_size - 1);
            
            // Map the faulting page
            if (map_single_page(fault_addr, page_offset) == MAP_FAILED) {
                perror("mmap in fault handler");
                exit(1);
            }
            
            // Predict and map additional pages
            predict_and_map_pages(fault_addr, ph);
            return;
        }
    }
    
    // If we get here, it's a real segfault
    fprintf(stderr, "Segmentation fault at address %p\n", fault_addr);
    exit(1);
}

// Function prototypes
static void validate_elf(Elf64_Ehdr* ehdr);
static void hybrid_load_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr);
static void setup_stack(program_info_t* info);
static void transfer_control(program_info_t* info) __attribute__((noreturn));

int main(int argc, char** argv, char** envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(1);
    }

    page_size = sysconf(_SC_PAGESIZE);

    // Initialize statistics
    prog_state.page_faults = 0;
    prog_state.pages_mapped = 0;
    clock_gettime(CLOCK_MONOTONIC, &prog_state.start_time);

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

    // Set up global state
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

    program_info_t prog_info = {
        .entry_point = (void*)ehdr.e_entry,
        .stack_size = 8 * 1024 * 1024,
        .argv = argv + 1,
        .argc = argc - 1,
        .envp = envp
    };

    // Hybrid load segments
    hybrid_load_segments(fd, &ehdr, phdr);
    
    setup_stack(&prog_info);

    // Transfer control to loaded program
    transfer_control(&prog_info);
}

static void hybrid_load_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        void* page_addr = (void*)(phdr[i].p_vaddr & ~(page_size - 1));
        size_t page_offset = phdr[i].p_vaddr & (page_size - 1);
        size_t mapping_size = phdr[i].p_memsz + page_offset;

        // If segment has initialized data or is executable, map it immediately
        if (phdr[i].p_filesz > 0 || (phdr[i].p_flags & PF_X)) {
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
            
            prog_state.pages_mapped += (mapping_size + page_size - 1) / page_size;
            fprintf(stderr, "Mapped initialized segment at %p, size %zu\n", 
                    addr, mapping_size);
        }
        // Otherwise (BSS), just reserve address space
        else {
            void* addr = mmap(
                page_addr,
                mapping_size,
                PROT_NONE,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                -1,
                0
            );

            if (addr == MAP_FAILED) {
                perror("mmap");
                exit(1);
            }
            
            fprintf(stderr, "Reserved BSS segment at %p, size %zu\n", 
                    addr, mapping_size);
        }
    }
}

// Print statistics at exit
static void __attribute__((destructor)) print_stats(void) {
    clock_gettime(CLOCK_MONOTONIC, &prog_state.end_time);
    double elapsed = (prog_state.end_time.tv_sec - prog_state.start_time.tv_sec) +
                    (prog_state.end_time.tv_nsec - prog_state.start_time.tv_nsec) 
                    / 1e9;
    
    fprintf(stderr, "\nProgram Statistics:\n");
    fprintf(stderr, "Total page faults: %zu\n", prog_state.page_faults);
    fprintf(stderr, "Total pages mapped: %zu\n", prog_state.pages_mapped);
    fprintf(stderr, "Execution time: %.6f seconds\n", elapsed);
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