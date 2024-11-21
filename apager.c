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

    // Stack grows down - start at the top and align to 16 bytes
    // Add 8 bytes to account for the push we'll do later
    void* stack_top = (void*)((((uintptr_t)stack + info->stack_size) - 8) & ~0xFULL);
    uint64_t* stack_ptr = (uint64_t*)stack_top;
    
    // Count environment variables
    int envc = 0;
    for (char** env = info->envp; *env != NULL; env++) {
        envc++;
    }

    // Calculate total items we'll push (for alignment)
    int total_items = 1 + // argc
                     info->argc + 1 + // argv + NULL
                     envc + 1;  // envp + NULL

    // Adjust stack pointer to maintain alignment after pushing all items
    if (total_items % 2 == 0) {
        stack_ptr--; // Add extra padding for alignment
    }
    
    // Write values from bottom up
    uint64_t* base = stack_ptr;
    
    // Push argc
    *stack_ptr-- = info->argc;
    
    // Push argv pointers
    char** argv_base = (char**)stack_ptr;
    for (int i = 0; i < info->argc; i++) {
        *stack_ptr-- = (uint64_t)info->argv[i];
    }
    *stack_ptr-- = 0;  // NULL terminator
    
    // Push envp pointers
    char** envp_base = (char**)stack_ptr;
    for (int i = 0; i < envc; i++) {
        *stack_ptr-- = (uint64_t)info->envp[i];
    }
    *stack_ptr-- = 0;  // NULL terminator

    // Return to the base for the actual stack pointer
    info->prog_stack = base;

    // Verify alignment
    fprintf(stderr, "Stack alignment check:\n");
    fprintf(stderr, "  Base address: %p\n", base);
    fprintf(stderr, "  Alignment offset: %lu\n", (unsigned long)base & 0xF);
    
    if (((unsigned long)base & 0xF) != 0) {
        fprintf(stderr, "Warning: Stack is not 16-byte aligned!\n");
    }

    fprintf(stderr, "Stack setup:\n");
    fprintf(stderr, "  Base address: %p\n", stack);
    fprintf(stderr, "  Stack pointer: %p\n", base);
    fprintf(stderr, "  argv base: %p\n", argv_base);
    fprintf(stderr, "  envp base: %p\n", envp_base);
    fprintf(stderr, "  argc: %d\n", info->argc);
}


static void transfer_control(program_info_t* info) {

    register unsigned long stack asm("rsp") = (unsigned long)info->prog_stack;
    register int argc asm("rdi") = info->argc;
    register char** argv asm("rsi") = (char**)((char*)info->prog_stack + 8);
    register char** envp asm("rdx") = argv + info->argc + 1;
    register unsigned long entry asm("r11") = (unsigned long)info->entry_point;


    // Before assembly block
    if (((uintptr_t)stack & 0xf) != 0) {
        fprintf(stderr, "Stack not properly aligned\n");
        exit(1);
    }


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
        "xor %%rbp, %%rbp\n"  // Clear frame pointer
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
          "r12", "r13", "r14", "r15"
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