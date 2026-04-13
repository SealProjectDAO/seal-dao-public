/* Linker script for risc0 zkVM guest.
   TEXT starts at 0x0020_0800, stack at 0x0020_0400.
   See vendor/risc0-zkvm-platform/src/memory.rs for layout. */

ENTRY(__start)

SECTIONS
{
    . = 0x00200800;
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) }
    _end = .;
}
