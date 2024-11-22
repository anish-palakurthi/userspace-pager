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
#include <errno.h>

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
    // Verify file first
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        exit(1);
    }
    fprintf(stderr, "File size: %ld bytes\n", st.st_size);

    fprintf(stderr, "Entry point: %lx\n", (unsigned long)ehdr->e_entry);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        size_t page_size = sysconf(_SC_PAGESIZE);
        uintptr_t vaddr = phdr[i].p_vaddr;
        uintptr_t aligned_vaddr = vaddr & ~0x3FULL; // Align vaddr to 64-byte boundary
        uintptr_t aligned_addr = aligned_vaddr & ~(page_size - 1);
        size_t page_offset = aligned_vaddr & (page_size - 1);
        
        // Verify segment size doesn't exceed file size
        if (phdr[i].p_offset + phdr[i].p_filesz > (size_t)st.st_size) {
            fprintf(stderr, "Segment extends beyond file size\n");
            exit(1);
        }

        size_t mapping_size = phdr[i].p_memsz + page_offset;
        mapping_size = (mapping_size + page_size - 1) & ~(page_size - 1);

        off_t offset = phdr[i].p_offset & ~(page_size - 1);

        // Set permissions - start with RW
        int initial_prot = PROT_READ | PROT_WRITE;
        int final_prot = PROT_NONE;
        if (phdr[i].p_flags & PF_R) final_prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) final_prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) final_prot |= PROT_EXEC;

        fprintf(stderr, "Mapping segment %d:\n", i);
        fprintf(stderr, "  vaddr: 0x%lx\n", vaddr);
        fprintf(stderr, "  offset in file: 0x%lx\n", phdr[i].p_offset);
        fprintf(stderr, "  filesz: %lu\n", phdr[i].p_filesz);
        fprintf(stderr, "  memsz: %lu\n", phdr[i].p_memsz);
        fprintf(stderr, "  flags: 0x%x\n", phdr[i].p_flags);
        fprintf(stderr, "  final_prot: 0x%x\n", final_prot);

        // Try to read from file at offset to verify
        char verify_buf[1];
        if (pread(fd, verify_buf, 1, phdr[i].p_offset) != 1) {
            perror("pread verify");
            exit(1);
        }

        // First mapping
        void* mapped = mmap(
            (void*)aligned_addr,  // Use aligned address
            mapping_size,
            initial_prot,
            MAP_PRIVATE,
            fd,
            offset
        );


        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            void* bss_start = (void*)((uintptr_t)mapped + phdr[i].p_filesz);
            size_t bss_size = phdr[i].p_memsz - phdr[i].p_filesz;

            // Ensure bss_start is within the mapped region
            if ((uintptr_t)bss_start >= (uintptr_t)mapped &&
                (uintptr_t)bss_start < (uintptr_t)mapped + mapping_size) {
                
                // Calculate remaining space in the mapped region
                size_t remaining_space = ((uintptr_t)mapped + mapping_size) - (uintptr_t)bss_start;
                
                // Adjust bss_size if it exceeds the remaining space
                if (bss_size > remaining_space) {
                    bss_size = remaining_space;
                }

                // Zero out the BSS section
                memset(bss_start, 0, bss_size);
            } else {
                fprintf(stderr, "Warning: BSS section outside mapped region\n");
            }
        }

        // Set final permissions
        if (mprotect(mapped, mapping_size, final_prot) == -1) {
            perror("mprotect");
            exit(1);
        }

        fprintf(stderr, "Successfully mapped segment %d at %p\n", i, mapped);
    }

    // Verify final mappings
    fprintf(stderr, "Final memory mappings:\n");
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", getpid());
    system(cmd);
}

static void setup_stack(program_info_t* info) {
    // Map stack with fixed address - use a lower address to avoid conflicts
    const size_t page_size = sysconf(_SC_PAGESIZE);
    size_t aligned_stack_size = (info->stack_size + page_size - 1) & ~(page_size - 1);
    
    // Use a different stack address that's less likely to conflict
    void* stack_addr = (void*)0x700000000000;  // 128TB range
    void* stack = mmap(
        stack_addr,
        aligned_stack_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,  // Removed MAP_FIXED to let kernel choose if needed
        -1,
        0
    );

    if (stack == MAP_FAILED) {
        perror("mmap stack");
        fprintf(stderr, "Errno: %d\n", errno);
        exit(1);
    }

    fprintf(stderr, "Stack allocated at: %p\n", stack);

    // Setup the stack layout
    // Calculate where our strings will go
    size_t total_strings_size = 0;
    int envc = 0;
    
    // Calculate space needed for argv strings
    for (int i = 0; i < info->argc; i++) {
        total_strings_size += strlen(info->argv[i]) + 1;
    }
    
    // Calculate space needed for envp strings
    for (char** env = info->envp; *env != NULL; env++) {
        total_strings_size += strlen(*env) + 1;
        envc++;
    }

    // Calculate total space needed
    size_t stack_data_size = 
        8 +                         // argc
        ((info->argc + 1) * 8) +   // argv + NULL
        ((envc + 1) * 8) +         // envp + NULL
        16 +                       // minimal auxv (2 entries)
        total_strings_size;        // actual strings

    // Align to 16 bytes
    stack_data_size = (stack_data_size + 15) & ~15;

    // Place stack_top near the end of our allocation, properly aligned
    void* stack_top = (void*)((uintptr_t)(stack + aligned_stack_size - stack_data_size) & ~15ULL);

    fprintf(stderr, "Stack data setup:\n");
    fprintf(stderr, "  Stack top will be at: %p\n", stack_top);
    fprintf(stderr, "  Total stack data size: %zu\n", stack_data_size);
    fprintf(stderr, "  Distance from base: %ld\n", (char*)stack_top - (char*)stack);

    // Write argc
    *(long*)stack_top = info->argc;

    // Setup argv pointers array
    char** argv_ptr = (char**)(stack_top + 8);
    char* str_area = (char*)(stack_top + 8 + ((info->argc + 1) * 8) + ((envc + 1) * 8) + 16);

    // Copy argv strings and set up pointers
    for (int i = 0; i < info->argc; i++) {
        size_t len = strlen(info->argv[i]) + 1;
        memcpy(str_area, info->argv[i], len);
        argv_ptr[i] = str_area;
        str_area += len;
    }
    argv_ptr[info->argc] = NULL;

    // Setup envp pointers array
    char** envp_ptr = argv_ptr + info->argc + 1;
    
    // Copy environment strings and set up pointers
    for (int i = 0; i < envc; i++) {
        size_t len = strlen(info->envp[i]) + 1;
        memcpy(str_area, info->envp[i], len);
        envp_ptr[i] = str_area;
        str_area += len;
    }
    envp_ptr[envc] = NULL;

    // Set up minimal auxv
    Elf64_auxv_t* auxv = (Elf64_auxv_t*)(envp_ptr + envc + 1);
    auxv[0].a_type = AT_NULL;
    auxv[0].a_un.a_val = 0;

    // Test read access
    fprintf(stderr, "Stack verification:\n");
    fprintf(stderr, "  argc = %ld\n", *(long*)stack_top);
    fprintf(stderr, "  argv[0] = %s\n", argv_ptr[0]);
    if (envp_ptr[0]) {
        fprintf(stderr, "  envp[0] = %s\n", envp_ptr[0]);
    }

    // Store stack pointer
    info->prog_stack = stack_top;

    // Final verification
    fprintf(stderr, "Final stack alignment check: %ld\n", (unsigned long)stack_top & 15);
    
    // Show memory mappings
    fprintf(stderr, "Memory map before transfer:\n");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", getpid());
    system(cmd);
}

static void transfer_control(program_info_t* info) {
    void* stack_top = info->prog_stack;
    void* entry = info->entry_point;
    
    // Debug prints
    fprintf(stderr, "Transfer details:\n");
    fprintf(stderr, "  Stack top: %p\n", stack_top);
    fprintf(stderr, "  Stack alignment: %lx\n", (unsigned long)stack_top & 0xf);
    fprintf(stderr, "  Entry point: %p\n", entry);
    fprintf(stderr, "  First stack value: %lx\n", *(unsigned long*)stack_top);

    // Make sure memory operations are complete
    __sync_synchronize();

    asm volatile (
        // First move stack and entry point to registers we control
        "mov %[stack], %%r11\n\t"
        "mov %[entry], %%r12\n\t"
        
        // Clear essential registers
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdi, %%rdi\n\t"
        // "xor %%rbp, %%rbp\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"

        // Set up stack with saved value
        "mov %%r11, %%rsp\n\t"
        
        // Set up args carefully - first test if we can read stack
        "testq %%rsp, %%rsp\n\t"      // Verify RSP is valid
        "mov (%%rsp), %%rdi\n\t"      // argc -> rdi
        "lea 8(%%rsp), %%rsi\n\t"     // argv -> rsi
        "lea 8(%%rsp,%%rdi,8), %%rdx\n\t" // envp -> rdx
        "addq $8, %%rdx\n\t"
        
        // Clear direction flag
        "cld\n\t"
        
        // Move entry point and jump
        "mov %%r12, %%rax\n\t"
        "jmpq *%%rax\n\t"
        : // no outputs
        : [stack] "m" (stack_top),
          [entry] "m" (entry)
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13",
          "r14", "r15", "memory", "cc"
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