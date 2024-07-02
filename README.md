# RISC-V RV32I Disassembler

This project implements a disassembler for the RISC-V RV32I instruction set. The disassembler produces output similar to the GNU objdump utility.

## Features

- Parses ELF32 files for RISC-V architecture
- Disassembles RV32I instructions
- Displays section headers
- Displays symbol table
- Outputs in a format similar to objdump

## Files

- `my_objdump.c`: Main source file containing the disassembler implementation
- `riscv.h`: Header file with RISC-V instruction definitions
- `conversions.c` and `conversions.h`: Utility functions for number conversions
- `elf.h`: ELF file format structures
- `Makefile`: Build configuration

## Building

To build the project, simply run: make

This will compile the source files and create an executable named `my_objdump`.

## Usage

The disassembler supports three main operations:

1. Display section headers: ./my_objdump -h <elf_file>
2. Display symbol table: ./my_objdump -t <elf_file>
3. Disassemble code: ./my_objdump -d <elf_file>

## Implementation Details

- The disassembler reads ELF32 files and extracts relevant information from the file header and section headers.
- It supports all RV32I base instruction set operations.
- The output format closely mimics that of the GNU objdump utility.
- The project uses bitfield structures to efficiently decode RISC-V instructions.

## Notes

- This implementation focuses on the RV32I base instruction set. It does not support extensions like M, A, F, D, etc.
- The disassembler assumes little-endian encoding for instructions.

## Dependencies

- GCC compiler
- Standard C libraries

## Compilation Flags

The project uses strict compilation flags to ensure code quality and catch potential issues:

- `-g3`: Maximum debugging information
- `-std=c11`: C11 standard
- Various warning flags (`-Wall`, `-Wextra`, `-Wshadow`, etc.)
- Address sanitizer and undefined behavior sanitizer flags

These flags help maintain code quality and catch potential runtime errors during development.
