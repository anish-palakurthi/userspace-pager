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
    void* phdr;      // Program header location
    uint16_t phnum;  // Number of program headers
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
static void map_program_segments(int fd, Elf64_Ehdr* ehdr, Elf64_Phdr* phdr, program_info_t* info) {
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        exit(1);
    }
    fprintf(stderr, "File size: %ld bytes\n", st.st_size);
    fprintf(stderr, "Entry point: %lx\n", (unsigned long)ehdr->e_entry);

    const size_t page_size = sysconf(_SC_PAGESIZE);
    void* first_load = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        // Calculate alignment and offsets
        uintptr_t vaddr = phdr[i].p_vaddr;
        uintptr_t offset = phdr[i].p_offset & ~(page_size - 1);
        uintptr_t aligned_vaddr = vaddr & ~(page_size - 1);
        size_t page_offset = vaddr & (page_size - 1);

        // Verify segment boundaries
        if (phdr[i].p_offset + phdr[i].p_filesz > (size_t)st.st_size) {
            fprintf(stderr, "Segment extends beyond file size\n");
            exit(1);
        }

        // Calculate mapping size (include page alignment)
        size_t mapping_size = phdr[i].p_memsz + page_offset;
        mapping_size = (mapping_size + page_size - 1) & ~(page_size - 1);

        fprintf(stderr, "Mapping segment %d:\n", i);
        fprintf(stderr, "  vaddr: 0x%lx\n", vaddr);
        fprintf(stderr, "  aligned_vaddr: 0x%lx\n", aligned_vaddr);
        fprintf(stderr, "  offset: 0x%lx\n", offset);
        fprintf(stderr, "  filesz: %lu\n", phdr[i].p_filesz);
        fprintf(stderr, "  memsz: %lu\n", phdr[i].p_memsz);
        fprintf(stderr, "  mapping_size: %lu\n", mapping_size);

        // Initial mapping with PROT_WRITE
        int initial_prot = PROT_READ | PROT_WRITE;
        void* mapped = mmap(
            (void*)aligned_vaddr,
            mapping_size,
            initial_prot,
            MAP_PRIVATE | MAP_FIXED_NOREPLACE,  // Try fixed mapping but fail if occupied
            fd,
            offset
        );

        if (mapped == MAP_FAILED) {
            // If fixed mapping failed, try without MAP_FIXED
            mapped = mmap(
                NULL,
                mapping_size,
                initial_prot,
                MAP_PRIVATE,
                fd,
                offset
            );
            
            if (mapped == MAP_FAILED) {
                perror("mmap");
                fprintf(stderr, "Failed to map segment at address 0x%lx\n", aligned_vaddr);
                exit(1);
            }
        }

        // Track first PT_LOAD for phdr calculations
        if (first_load == NULL) {
            first_load = mapped;
            info->phdr = (void*)((uintptr_t)mapped + (ehdr->e_phoff & (page_size - 1)));
            info->phnum = ehdr->e_phnum;
        }

        // Handle BSS section
        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            size_t bss_offset = phdr[i].p_filesz;
            size_t bss_size = phdr[i].p_memsz - phdr[i].p_filesz;
            void* bss_start = (void*)((uintptr_t)mapped + bss_offset);

            fprintf(stderr, "  Zeroing BSS: start=%p size=%lu\n", bss_start, bss_size);
            memset(bss_start, 0, bss_size);
        }

        // Set final permissions
        int final_prot = PROT_NONE;
        if (phdr[i].p_flags & PF_R) final_prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W) final_prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X) final_prot |= PROT_EXEC;

        if (mprotect(mapped, mapping_size, final_prot) == -1) {
            perror("mprotect");
            fprintf(stderr, "Failed to set segment permissions\n");
            exit(1);
        }

        fprintf(stderr, "Successfully mapped segment %d at %p\n", i, mapped);
    }

    // Verify mappings
    fprintf(stderr, "Final memory mappings:\n");
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", getpid());

    info->phdr = (void*)(ehdr->e_phoff + phdr[0].p_vaddr); // Use virtual address
info->phnum = ehdr->e_phnum;
    system(cmd);
}

static void setup_stack(program_info_t* info) {
    const size_t page_size = sysconf(_SC_PAGESIZE);
    size_t aligned_stack_size = (info->stack_size + page_size - 1) & ~(page_size - 1);
    
    // Map stack with guard page
    size_t total_stack_size = aligned_stack_size + page_size;
    void* stack = mmap(
        NULL,  // Let kernel choose address
        total_stack_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
        -1,
        0
    );

    if (stack == MAP_FAILED) {
        perror("mmap stack");
        exit(1);
    }

    // Set up guard page
    if (mprotect(stack, page_size, PROT_NONE) == -1) {
        perror("mprotect guard page");
        exit(1);
    }

    void* stack_base = (char*)stack + page_size;
    
    // Count environment variables
    int envc = 0;
    for (char** env = info->envp; *env != NULL; env++) {
        envc++;
    }

    // Calculate sizes
    size_t auxv_count = 20;  // Increased for completeness
    size_t total_strings_size = 0;
    
    for (int i = 0; i < info->argc; i++) {
        total_strings_size += strlen(info->argv[i]) + 1;
    }
    for (int i = 0; i < envc; i++) {
        total_strings_size += strlen(info->envp[i]) + 1;
    }
    
    // Platform string
    const char* platform = "x86_64";
    total_strings_size += strlen(platform) + 1;

    size_t stack_data_size = 
        8 +                         // argc
        ((info->argc + 1) * 8) +   // argv + NULL
        ((envc + 1) * 8) +         // envp + NULL
        (auxv_count * 16) +        // auxv entries
        total_strings_size +       // strings
        16;                        // Final alignment padding

    // Align to 16 bytes
    stack_data_size = (stack_data_size + 15) & ~15;

    // Place stack_top near end
    void* stack_top = (void*)((uintptr_t)(stack_base + aligned_stack_size - stack_data_size) & ~15ULL);
    
    // Clear the stack area
    memset(stack_top, 0, stack_data_size);

    // Write argc
    *(long*)stack_top = info->argc;

    // Setup argv
    char** argv_ptr = (char**)(stack_top + 8);
    char* str_area = (char*)(stack_top + 8 + ((info->argc + 1) * 8) + ((envc + 1) * 8) + (auxv_count * 16));

    // Copy argv strings
    for (int i = 0; i < info->argc; i++) {
        size_t len = strlen(info->argv[i]) + 1;
        memcpy(str_area, info->argv[i], len);
        argv_ptr[i] = str_area;
        str_area += len;
    }
    argv_ptr[info->argc] = NULL;

    // Setup envp
    char** envp_ptr = argv_ptr + info->argc + 1;
    for (int i = 0; i < envc; i++) {
        size_t len = strlen(info->envp[i]) + 1;
        memcpy(str_area, info->envp[i], len);
        envp_ptr[i] = str_area;
        str_area += len;
    }
    envp_ptr[envc] = NULL;

    // Copy platform string
    char* platform_str = str_area;
    strcpy(platform_str, platform);
    str_area += strlen(platform) + 1;

    // Setup auxv
    Elf64_auxv_t* auxv = (Elf64_auxv_t*)(envp_ptr + envc + 1);
    int aux_index = 0;

    auxv[aux_index++] = (Elf64_auxv_t){AT_PHDR, (uint64_t)info->phdr};
    auxv[aux_index++] = (Elf64_auxv_t){AT_PHENT, sizeof(Elf64_Phdr)};
    auxv[aux_index++] = (Elf64_auxv_t){AT_PHNUM, info->phnum};
    auxv[aux_index++] = (Elf64_auxv_t){AT_PAGESZ, page_size};
    auxv[aux_index++] = (Elf64_auxv_t){AT_BASE, 0};
    auxv[aux_index++] = (Elf64_auxv_t){AT_FLAGS, 0};
    auxv[aux_index++] = (Elf64_auxv_t){AT_ENTRY, (uint64_t)info->entry_point};
    auxv[aux_index++] = (Elf64_auxv_t){AT_UID, getuid()};
    auxv[aux_index++] = (Elf64_auxv_t){AT_EUID, geteuid()};
    auxv[aux_index++] = (Elf64_auxv_t){AT_GID, getgid()};
    auxv[aux_index++] = (Elf64_auxv_t){AT_EGID, getegid()};
    auxv[aux_index++] = (Elf64_auxv_t){AT_SECURE, 0};
    auxv[aux_index++] = (Elf64_auxv_t){AT_RANDOM, (uint64_t)str_area}; // Use string area for random bytes
    auxv[aux_index++] = (Elf64_auxv_t){AT_PLATFORM, (uint64_t)platform_str};
    auxv[aux_index++] = (Elf64_auxv_t){AT_HWCAP, 0};
    auxv[aux_index++] = (Elf64_auxv_t){AT_CLKTCK, sysconf(_SC_CLK_TCK)};
    auxv[aux_index++] = (Elf64_auxv_t){AT_NULL, 0};

    info->prog_stack = stack_top;
}

static void transfer_control(program_info_t* info) {
    void* stack_top = info->prog_stack;
    void* entry = info->entry_point;

    fprintf(stderr, "Transfer details:\n");
    fprintf(stderr, "  Stack top: %p\n", stack_top);
    fprintf(stderr, "  Stack alignment: %lx\n", (unsigned long)stack_top & 0xf);
    fprintf(stderr, "  Entry point: %p\n", entry);
    fprintf(stderr, "  First stack value: %lx\n", *(unsigned long*)stack_top);

    __sync_synchronize();



    asm volatile (

                    // Set up stack pointer
        "mov %[stack_top], %%rsp\n\t"
        
        // Push entry point
        "push %[entry]\n\t"



        // Load arguments per x86_64 calling convention
        "mov (%%rsp), %%rdi\n\t"          // argc -> rdi (1st arg)
        "lea 8(%%rsp), %%rsi\n\t"         // argv -> rsi (2nd arg)
        "lea 8(%%rsp,%%rdi,8), %%rdx\n\t" // calc envp position
        "add $8, %%rdx\n\t"               // adjust envp

        // Clear all general-purpose registers
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        // "xor %%rdx, %%rdx\n\t"
        // "xor %%rsi, %%rsi\n\t"
        // "xor %%rdi, %%rdi\n\t"

        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"



        // Clear direction flag
        "cld\n\t"

        // Call entry point
        "ret\n\t"

        :
        : [stack_top] "r" (stack_top),
        [entry] "r" (entry)
        : "memory", "cc", "rsp", "rdi", "rsi", "rdx"
    );
    __builtin_unreachable();
    }

int main(int argc, char** argv, char** envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(1);
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read ehdr");
        exit(1);
    }

    validate_elf(&ehdr);

    Elf64_Phdr* phdr = malloc(ehdr.e_phentsize * ehdr.e_phnum);
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
        perror("lseek");
        exit(1);
    }
    if (read(fd, phdr, ehdr.e_phentsize * ehdr.e_phnum) != 
        ehdr.e_phentsize * ehdr.e_phnum) {
        perror("read phdr");
        exit(1);
    }

    program_info_t prog_info = {
        .entry_point = (void*)ehdr.e_entry,
        .stack_size = 8 * 1024 * 1024,
        .argv = argv + 1,
        .argc = argc - 1,
        .envp = envp
    };

    map_program_segments(fd, &ehdr, phdr, &prog_info);
    setup_stack(&prog_info);

    transfer_control(&prog_info);
    return 0;
}

