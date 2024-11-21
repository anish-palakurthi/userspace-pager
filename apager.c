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
    // Map stack with fixed address to avoid conflicts
    void* stack_addr = (void*)0x7ffff7000000;  // Choose a high address
    void* stack = mmap(
        stack_addr,
        info->stack_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_FIXED,
        -1,
        0
    );

    if (stack == MAP_FAILED) {
        fprintf(stderr, "Stack allocation failed: %s\n", strerror(errno));
        exit(1);
    }

    // Calculate space needed for strings
    size_t strings_size = 0;
    for (int i = 0; i < info->argc; i++) {
        strings_size += strlen(info->argv[i]) + 1;
    }
    
    // Count and measure environment variables
    int envc = 0;
    for (char** env = info->envp; *env != NULL; env++) {
        strings_size += strlen(*env) + 1;
        envc++;
    }

    // Calculate total space needed
    size_t total_size = strings_size +
                       (info->argc + 1) * sizeof(char*) +  // argv array + NULL
                       (envc + 1) * sizeof(char*) +        // envp array + NULL
                       sizeof(long);                       // argc

    // Align stack top and reserve space
    void* stack_top = (void*)((((uintptr_t)stack + info->stack_size) - total_size) & ~0xFULL);
    
    // String area starts after the arrays
    char* string_area = (char*)stack_top + sizeof(long) +
                       (info->argc + 1) * sizeof(char*) +
                       (envc + 1) * sizeof(char*);

    // Setup arrays
    long* argc_ptr = (long*)stack_top;
    char** argv_ptr = (char**)(argc_ptr + 1);
    char** envp_ptr = argv_ptr + info->argc + 1;
    
    // Copy argc
    *argc_ptr = info->argc;
    
    // Copy argv strings and setup pointers
    char* curr_str = string_area;
    for (int i = 0; i < info->argc; i++) {
        size_t len = strlen(info->argv[i]) + 1;
        memcpy(curr_str, info->argv[i], len);
        argv_ptr[i] = curr_str;
        curr_str += len;
    }
    argv_ptr[info->argc] = NULL;  // NULL terminate argv

    // Copy environment strings and setup pointers
    for (int i = 0; i < envc; i++) {
        size_t len = strlen(info->envp[i]) + 1;
        memcpy(curr_str, info->envp[i], len);
        envp_ptr[i] = curr_str;
        curr_str += len;
    }
    envp_ptr[envc] = NULL;  // NULL terminate envp

    // Store stack pointer
    info->prog_stack = stack_top;

    // Verify setup
    fprintf(stderr, "Stack layout verification:\n");
    fprintf(stderr, "  argc = %ld\n", *argc_ptr);
    fprintf(stderr, "  argv[0] = %s\n", argv_ptr[0]);
    fprintf(stderr, "  Stack base: %p\n", stack);
    fprintf(stderr, "  Stack top: %p\n", stack_top);
    fprintf(stderr, "  argv array: %p\n", argv_ptr);
    fprintf(stderr, "  envp array: %p\n", envp_ptr);
    fprintf(stderr, "  String area: %p\n", string_area);
    fprintf(stderr, "  Alignment check: %lx\n", (unsigned long)stack_top & 0xF);
}



static void transfer_control(program_info_t* info) {
    // Get our stack layout pointers
    void* stack_top = info->prog_stack;
    long* argc_ptr = (long*)stack_top;
    char** argv_ptr = (char**)(argc_ptr + 1);
    char** envp_ptr = argv_ptr + info->argc + 1;

    // Verify our data is correct before transfer
    fprintf(stderr, "Pre-transfer verification:\n");
    fprintf(stderr, "  Entry point: 0x%lx\n", (unsigned long)info->entry_point);
    fprintf(stderr, "  argc value: %ld at %p\n", *argc_ptr, argc_ptr);
    fprintf(stderr, "  argv[0]: %s at %p\n", argv_ptr[0], argv_ptr);
    fprintf(stderr, "  envp[0]: %s at %p\n", envp_ptr[0], envp_ptr);

    // Force the compiler to use specific registers
    unsigned long entry = (unsigned long)info->entry_point;
    unsigned long stack = (unsigned long)stack_top;
    int argc = (int)*argc_ptr;

    // Clear direction flag
    asm volatile("cld\n");

    // Use specific registers and prevent compiler reordering
    asm volatile(
        "movq %0, %%rsp\n"     // Set stack pointer
        "movq %1, %%rdi\n"     // Set argc
        "movq %2, %%rsi\n"     // Set argv
        "movq %3, %%rdx\n"     // Set envp
        "xor %%rax, %%rax\n"   // Clear rax
        "xor %%rbx, %%rbx\n"   // Clear rbx
        "xor %%rbp, %%rbp\n"   // Clear rbp
        "xor %%rcx, %%rcx\n"   // Clear rcx
        "xor %%r8,  %%r8\n"    // Clear r8
        "xor %%r9,  %%r9\n"    // Clear r9
        "xor %%r10, %%r10\n"   // Clear r10
        "xor %%r11, %%r11\n"   // Clear r11
        "xor %%r12, %%r12\n"   // Clear r12
        "xor %%r13, %%r13\n"   // Clear r13
        "xor %%r14, %%r14\n"   // Clear r14
        "xor %%r15, %%r15\n"   // Clear r15
        "movq %4, %%rax\n"     // Put entry point in rax
        "jmpq *%%rax\n"        // Jump to entry point
        : // No outputs
        : "r"(stack),
          "r"((long)argc),
          "r"(argv_ptr),
          "r"(envp_ptr),
          "r"(entry)
        : "memory"
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