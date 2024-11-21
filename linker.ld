SECTIONS
{
  /* Executable code starts at 0x400000 */
  .text 0x400000 : {
    *(.text.startup)
    *(.text)
  }
  
  /* Read-only data */
  .rodata ALIGN(4096) : {
    *(.rodata)
  }
  
  /* Initialized data */
  .data ALIGN(4096) : {
    *(.data)
  }
  
  /* BSS section */
  .bss ALIGN(4096) : {
    *(.bss)
    *(COMMON)
  }
}

ENTRY(_start)