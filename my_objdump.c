#include <fcntl.h>
#include <unistd.h>
#define MAX_SIZE 100004
#define MAX_INDEX_DIGITS 2
#define DECIMAL_SIZE 12 
#define PADDED_HEX_SIZE 8
#define SIZE_BIN 34
#define SIZE_HEX 8
#define EI_NIDENT 16

unsigned char file_data[MAX_SIZE];

static char regs_alias[32][5] ={
    "zero", "ra",  "sp",  "gp", "tp",
    "t0",   "t1",  "t2",  "s0", "s1",
    "a0",   "a1",  "a2",  "a3", "a4",
    "a5",   "a6",  "a7",  "s2", "s3",
    "s4",   "s5",  "s6",  "s7", "s8",
    "s9",   "s10", "s11", "t3", "t4",
    "t5",   "t6"
};

typedef unsigned int   Elf32_Addr;
typedef unsigned int   Elf32_Off;
typedef unsigned short Elf32_Half;
typedef unsigned int   Elf32_Word;
typedef unsigned int   Elf32_Sword;

typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    Elf32_Half      e_type;
    Elf32_Half      e_machine;
    Elf32_Word      e_version;
    Elf32_Addr      e_entry;
    Elf32_Off       e_phoff;
    Elf32_Off       e_shoff;
    Elf32_Word      e_flags;
    Elf32_Half      e_ehsize;
    Elf32_Half      e_phentsize;
    Elf32_Half      e_phnum;
    Elf32_Half      e_shentsize;
    Elf32_Half      e_shnum;
    Elf32_Half      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct {
	Elf32_Word	    st_name;
	Elf32_Addr	    st_value;
	Elf32_Word	    st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half	    st_shndx;
} Elf32_Sym;

typedef unsigned int uint;
enum rv_type {format_R, format_I, format_S, format_B, format_U, format_J, Unknown};

typedef union {
    struct {
        uint opcode : 7;
        uint rd     : 5;
        uint funct3 : 3;
        uint rs1    : 5;
        uint rs2    : 5;
        uint funct7 : 7;
    }rv_R;
    
    struct {
        uint opcode  : 7;
        uint rd      : 5;
        uint funct3  : 3;
        uint rs1     : 5;
        uint imm11_0 : 12;
    }rv_I;

    struct {
        uint opcode  : 7;
        uint imm4_0  : 5;
        uint funct3  : 3;
        uint rs1     : 5;
        uint rs2     : 5;
        uint imm11_5 : 7;
    }rv_S;

    struct {
        uint opcode  : 7;
        uint imm11   : 1;
        uint imm4_1  : 4;
        uint funct3  : 3;
        uint rs1     : 5;
        uint rs2     : 5;
        uint imm10_5 : 6;
        uint imm12   : 1;
    }rv_B;

    struct {
        uint opcode   : 7;
        uint rd       : 5;
        uint imm31_12 : 20;
    }rv_U;

    struct {
        uint opcode   : 7;
        uint rd       : 5;
        uint imm19_12 : 8;
        uint imm11    : 1;
        uint imm10_1  : 10;
        uint imm20    : 1;
    }rv_J;

    uint bits;
} rv_inst;


void int_to_unsigned_dec_str(unsigned int num, char *str);

void int_to_signed_dec_str(unsigned int num, char *str);

void int_to_padded_hex(unsigned int decimal, char* hex, int size_hex);

void int_to_hex(unsigned int decimal, char *hex);

void change_hex_endian(char *hex, char *big_hex, int size_hex);

unsigned int hex_to_uint(char *hex, int size_hex);

int num_digits(unsigned int n);

int num_hex_digits(unsigned int n);

unsigned int my_pow(int base, int exp);

unsigned int array_of_bytes_to_uint(const unsigned char *data, off_t offset, size_t size);

Elf32_Ehdr get_elf_header(const unsigned char *data);

Elf32_Shdr get_section_header(const unsigned char *data, const Elf32_Ehdr file_header, int index);

void print_section_headers(const unsigned char *data, const char *filename, const Elf32_Ehdr file_header, Elf32_Shdr);

void print_section_header(const unsigned char *data, const Elf32_Shdr s_hdr, const Elf32_Shdr shstrtab_h, int index);

void print_section_name(const unsigned char *data, const Elf32_Shdr s_hdr, const Elf32_Shdr shstrtab_h);

size_t stringlen(const char *str);

int stringcmp(const char *name, const char *ptr);

void print_paddedhex(unsigned int num);

void print_hex(unsigned int num);

Elf32_Shdr Shdr_from_section_name(const char *name, const unsigned char *data, const Elf32_Ehdr file_header, Elf32_Shdr shstrtab_h);

Elf32_Word sh_name_from_name(const char *name, const unsigned char *data, const Elf32_Ehdr file_header, const Elf32_Shdr shstrtab_h);

Elf32_Shdr Shdr_from_sh_name(const unsigned char *data, const Elf32_Ehdr file_header, Elf32_Word shname);

Elf32_Sym get_symbol_entry(const unsigned char *data, Elf32_Shdr symbol_table_h, int index);

void print_symbol_name(const unsigned char *data, const Elf32_Sym symbol, const Elf32_Shdr strtab_h);

void print_symbol_entry(const unsigned char *data, const Elf32_Ehdr file_header, const Elf32_Sym symbol, const Elf32_Shdr strtab_h, const Elf32_Shdr shstrtab_h);

void print_symbol_table(const unsigned char *data, const char *filename, const Elf32_Ehdr file_header, const Elf32_Sym *sym_array, Elf32_Shdr shstrtab_h, const Elf32_Shdr strtab_h, const Elf32_Shdr symtab_h);

void build_sym_array(const unsigned char *data, Elf32_Sym *sym_array, int n_symbols, Elf32_Shdr symtab_h);

void print_disassemble(const unsigned char *data, const char *filename, const Elf32_Sym *sym_array, int n_symbols, const Elf32_Ehdr file_header, Elf32_Shdr shstrtab_h, Elf32_Shdr strtab_h);

int is_symbol(off_t addr, const Elf32_Sym *sym_array, int n_symbols);

void print_spaced_hex(unsigned int num);

void decode(rv_inst encoding);

enum rv_type get_instruction_type(rv_inst encoding);

void print_unknown();

void print_fmt_3reg(rv_inst encoding, const char *str);

void print_fmt_2reg_rv_I(rv_inst encoding, const char *str);

void print_fmt_load(rv_inst encoding, const char* str);

void print_fmt_rv_U(rv_inst encoding, const char* str);

void print_fmt_store(rv_inst encoding, const char *str);

void print_fmt_rv_B(rv_inst encoding, const char *str);

void print_fmt_jal(rv_inst encoding, const char *str);

void check_fence_and_print(rv_inst encoding);

void print_fmt_ishif(rv_inst encoding, const char *str);

int main(int argc, char *argv[])
{
    if (argc != 3)
        return 1;

    char *flag = argv[1];
    char *path = argv[2];
    int fd = open(path, O_RDONLY);
    ssize_t file_size = read(fd, file_data, MAX_SIZE);
    int n_symbols;
    (void) file_size;

    Elf32_Ehdr file_header = get_elf_header(file_data);
    Elf32_Shdr shstrtab_h = get_section_header(file_data, file_header, file_header.e_shstrndx);
    Elf32_Shdr strtab_h = Shdr_from_section_name(".strtab", file_data, file_header, shstrtab_h);
    Elf32_Shdr symtab_h = Shdr_from_section_name(".symtab", file_data, file_header, shstrtab_h);

    if (symtab_h.sh_entsize != 0)
    {
        n_symbols = symtab_h.sh_size / symtab_h.sh_entsize;
    }
    else
    {
        n_symbols = 1;
    }

    Elf32_Sym sym_array[n_symbols];
    build_sym_array(file_data, sym_array, n_symbols, symtab_h);

    switch (flag[1])
    {
        case 'h':
            print_section_headers(file_data, path, file_header, shstrtab_h);
            break;
        case 't':
            print_symbol_table(file_data, path, file_header, sym_array, shstrtab_h, strtab_h, symtab_h);
            break;
        case 'd':
            print_disassemble(file_data, path, sym_array, n_symbols, file_header, shstrtab_h, strtab_h);
            break;
    }
}

void print_disassemble(const unsigned char *data, const char *filename, const Elf32_Sym *sym_array, int n_symbols, const Elf32_Ehdr file_header, Elf32_Shdr shstrtab_h, Elf32_Shdr strtab_h)
{
    char ini_str[] = "\n";
    size_t filename_size = stringlen(filename);
    char ini_str2[] = ":\tfile format ELF32-riscv\n\n\nDisassembly of section .text:\n";
    write(1, ini_str, 1);
    write(1, filename, filename_size);
    write(1, ini_str2, stringlen(ini_str2));

    Elf32_Shdr text_h = Shdr_from_section_name(".text", data, file_header, shstrtab_h);

    rv_inst encoding;
    off_t inst_off = 0;
    off_t curr_addr = text_h.sh_addr;
    off_t end_addr  = text_h.sh_addr + text_h.sh_size;
    int sym_index = 0;

    while (curr_addr != end_addr)
    {
        sym_index = is_symbol(curr_addr, sym_array, n_symbols);
        encoding.bits = array_of_bytes_to_uint(data + text_h.sh_offset, inst_off, 4);

        if (sym_index > 0)
        {
            write(1, "\n", 1);
            print_paddedhex(sym_array[sym_index].st_value);
            write(1, " ", 1);
            print_symbol_name(data, sym_array[sym_index], strtab_h);
            write(1, ":", 1);
            write(1, "\n", 1);
        }
        write(1,"   ", 3);
        print_hex(curr_addr);
        write(1, ": ", 2);
        print_spaced_hex(encoding.bits);
        write(1, "\t", 1);
        decode(encoding);
        write(1,"\t", 1); 

        write(1, "\n", 1);
        curr_addr += 4;
        inst_off += 4;
    }
}

void decode(rv_inst encoding)
{
    enum rv_type inst_type = get_instruction_type(encoding);

    switch (inst_type)
    {
        case format_I:
            switch (encoding.rv_I.opcode)
            {
                case 0x03: // 0000011
                    switch (encoding.rv_I.funct3)
                    {
                        case 0x0:
                            print_fmt_load(encoding, "lb");
                            break;
                        case 0x1:
                            print_fmt_load(encoding, "lh");
                            break;
                        case 0x2:
                            //write(1,"lw",2);
                            print_fmt_load(encoding, "lw");
                            break;
                        case 0x4:
                            print_fmt_load(encoding, "lbu");
                            break;
                        case 0x5:
                            print_fmt_load(encoding, "lhu");
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                case 0x0f: // 0001111 
                    switch (encoding.rv_I.rd)
                    {
                        case 0x0:
                            switch (encoding.rv_I.rs1)
                            {
                                case 0x0:
                                    check_fence_and_print(encoding);
                                    break;
                                default:
                                    print_unknown();
                                    break;
                            }
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                case 0x13: // 0010011
                    switch(encoding.rv_I.funct3)
                    {
                        case 0x0:
                            print_fmt_2reg_rv_I(encoding, "addi");
                            break;
                        case 0x1:
                            switch (encoding.rv_R.funct7)
                            {
                                case 0x0:
                                    print_fmt_ishif(encoding, "slli");
                                    break;
                                default:
                                    print_unknown();
                                    break;
                            }
                            break;
                        case 0x2:
                            print_fmt_2reg_rv_I(encoding, "slti");
                            break;
                        case 0x3:
                            print_fmt_2reg_rv_I(encoding, "sltiu");
                            break;
                        case 0x4:
                            print_fmt_2reg_rv_I(encoding, "xori");
                            break;
                        case 0x5:
                            switch (encoding.rv_R.funct7)
                            {
                                case 0x00:
                                    print_fmt_ishif(encoding, "srli");
                                    break;
                                case 0x20:
                                    print_fmt_ishif(encoding, "srai");
                                    break;
                                default:
                                    print_unknown();
                                    break;
                            }
                            break;
                        case 0x6:
                            print_fmt_2reg_rv_I(encoding, "ori");
                            break;
                        case 0x7:
                            print_fmt_2reg_rv_I(encoding, "andi");
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                case 0x67: // 1100111
                    switch (encoding.rv_R.funct3)
                    {
                        case 0x0:
                            print_fmt_load(encoding, "jalr");
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                case 0x73: // 1110011
                    switch (encoding.rv_I.funct3)
                    {
                        case 0x0:
                            switch (encoding.rv_I.rd)
                            {
                                case 0x0:
                                    switch(encoding.rv_I.rs1)
                                    {
                                        case 0x0:
                                            switch (encoding.rv_I.imm11_0)
                                            {
                                                case 0x0:
                                                    write(1,"ecall", 5);
                                                    break;
                                                case 0x1:
                                                    write(1,"ebreak", 6);
                                                    break;
                                                default:
                                                    print_unknown();
                                                    break;
                                            }
                                            break;
                                        default:
                                            print_unknown();
                                            break;
                                    }
                                    break;
                                default:
                                    print_unknown();
                                    break;
                            }
                            break;
                        case 0x1:
                            write(1,"csrrw",5);
                            break;
                        case 0x2:
                            write(1,"csrrs",5);
                            break;
                        case 0x3:
                            write(1,"csrrc",5);
                            break;
                        case 0x5:
                            write(1,"csrrwi",6);
                            break;
                        case 0x6:
                            write(1,"csrrsi",6);
                            break;
                        case 0x7:
                            write(1,"csrrci",6);
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                default:
                    print_unknown();
                    break;
            }
            break;
        case format_U:
            switch (encoding.rv_U.opcode)
            {
                case 0x37:
                    print_fmt_rv_U(encoding, "lui");
                    break;
                case 0x17:
                    print_fmt_rv_U(encoding, "auipc");
                    break;
                default:
                    print_unknown();
                    break;
            }
            break;
        case format_J:
            print_fmt_jal(encoding, "jal");
            break;
        case format_B:
            switch (encoding.rv_B.funct3)
            {
                case 0x0:
                    print_fmt_rv_B(encoding, "beq");
                    break;
                case 0x1:
                    print_fmt_rv_B(encoding, "bne");
                    break;
                case 0x4:
                    print_fmt_rv_B(encoding, "blt");
                    break;
                case 0x5:
                    print_fmt_rv_B(encoding, "bge");
                    break;
                case 0x6:
                    print_fmt_rv_B(encoding, "bltu");
                    break;
                case 0x7:
                    print_fmt_rv_B(encoding, "bgeu");
                    break;
                default:
                    print_unknown();
                    break;
            }
            break;
        case format_R:
            switch (encoding.rv_R.funct7)
            {
                case 0x0:
                    switch(encoding.rv_R.funct3)
                    {
                        case 0x0:
                            print_fmt_3reg(encoding, "add");
                            break;
                        case 0x1:
                            print_fmt_3reg(encoding, "sll");
                            break;
                        case 0x2:
                            print_fmt_3reg(encoding, "slt");
                            break;
                        case 0x3:
                            print_fmt_3reg(encoding, "sltu");
                            break;
                        case 0x4:
                            print_fmt_3reg(encoding, "xor");
                            break;
                        case 0x5:
                            print_fmt_3reg(encoding, "srl");
                            break;
                        case 0x6:
                            print_fmt_3reg(encoding, "or");
                            break;
                        case 0x7:
                            print_fmt_3reg(encoding, "and");
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                case 0x20:
                    switch(encoding.rv_R.funct3)
                    {
                        case 0x0:
                            print_fmt_3reg(encoding, "sub");
                            break;
                        case 0x5:
                            print_fmt_3reg(encoding, "sra");
                            break;
                        default:
                            print_unknown();
                            break;
                    }
                    break;
                default:
                    print_unknown();
                    break;
            }
            break;
        case format_S:
            switch (encoding.rv_S.funct3)
            {
                case 0x0:
                    print_fmt_store(encoding, "sb");
                    break;
                case 0x1:
                    print_fmt_store(encoding, "sh");
                    break;
                case 0x2:
                    print_fmt_store(encoding, "sw");
                    break;
                default:
                    print_unknown();
                    break;
            }
            break;
        case Unknown:
            print_unknown();
            break;
    }
}

void print_unknown()
{
    write(1,"<unknown>",9 );
}

void check_fence_and_print(rv_inst encoding)
{
    if (encoding.rv_I.imm11_0 >> 8)   
    {
        print_unknown();
    }
    else if (encoding.rv_I.funct3 == 0x0)
    {
        char decimal[DECIMAL_SIZE];
        int_to_unsigned_dec_str(( ( encoding.rv_I.imm11_0 >> 4 ) & 15) ,decimal); // pred
        write(1, "fence", 5);
        write(1, "\t", 1);
        write(1, decimal, stringlen(decimal));
        write(1, ", ", 1);
        int_to_unsigned_dec_str(( encoding.rv_I.imm11_0 & 15) ,decimal); // succ
        write(1, decimal, stringlen(decimal));

    }
    else if (encoding.rv_I.funct3 == 0)
    {
        write(1, "fence.i", 7);
    }
    else
        print_unknown();
}

void print_fmt_ishif(rv_inst encoding, const char *str)
{
    char decimal[DECIMAL_SIZE];
    int shamt = encoding.rv_R.rs2;

    int digits = num_digits(shamt);
    if (shamt < 0)
        digits++;

    int_to_signed_dec_str(shamt, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_I.rd], stringlen(regs_alias[encoding.rv_I.rd]));
    write(1, ", ", 2);
    write(1, regs_alias[encoding.rv_I.rs1], stringlen(regs_alias[encoding.rv_I.rs1]));
    write(1, ", ", 2);
    write(1, decimal, digits);
}

// inst rd, rs1, rs2
void print_fmt_3reg(rv_inst encoding, const char *str)
{
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_R.rd], stringlen(regs_alias[encoding.rv_R.rd]));
    write(1, ", ", 2);
    write(1, regs_alias[encoding.rv_R.rs1], stringlen(regs_alias[encoding.rv_R.rs1]));
    write(1, ", ", 2);
    write(1, regs_alias[encoding.rv_R.rs2], stringlen(regs_alias[encoding.rv_R.rs2]));
}

// inst rd, rs1, imm
void print_fmt_2reg_rv_I(rv_inst encoding, const char *str)
{
    char decimal[DECIMAL_SIZE];
    struct {signed int x:12;} s;
    int num = s.x = encoding.rv_I.imm11_0;

    int digits = num_digits(num);
    if (num < 0)
        digits++;

    int_to_signed_dec_str(num, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_R.rd], stringlen(regs_alias[encoding.rv_R.rd]));
    write(1, ", ", 2);
    write(1, regs_alias[encoding.rv_R.rs1], stringlen(regs_alias[encoding.rv_R.rs1]));
    write(1, ", ", 2);
    write(1, decimal, digits);
}

// inst rd, imm(rs1)
void print_fmt_load(rv_inst encoding, const char* str)
{
    char decimal[DECIMAL_SIZE];
    struct {signed int x:12;} s;
    int num = s.x = encoding.rv_I.imm11_0;

    int digits = num_digits(num);
    if (num < 0)
        digits++;

    int_to_signed_dec_str(num, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_R.rd], stringlen(regs_alias[encoding.rv_R.rd]));
    write(1, ", ", 2);
    write(1, decimal, digits);
    write(1, "(", 1);
    write(1, regs_alias[encoding.rv_R.rs1], stringlen(regs_alias[encoding.rv_R.rs1]));
    write(1, ")", 1);
}

//inst rd, imm
void print_fmt_rv_U(rv_inst encoding, const char* str)
{
    char decimal[DECIMAL_SIZE];
    int num = encoding.rv_U.imm31_12;

    int digits = num_digits(num);
    if (num < 0)
        digits++;

    int_to_signed_dec_str(num, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_R.rd], stringlen(regs_alias[encoding.rv_R.rd]));
    write(1, ", ", 2);
    write(1, decimal, digits);
}

// inst rs2, imm(rs1)
void print_fmt_store(rv_inst encoding, const char *str)
{
    char decimal[DECIMAL_SIZE];
    struct {signed int x:12;} s;
    int num = s.x = encoding.rv_S.imm4_0 | (encoding.rv_S.imm11_5 << 5);

    int digits = num_digits(num);
    if (num < 0)
        digits++;

    int_to_signed_dec_str(num, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_S.rs2], stringlen(regs_alias[encoding.rv_S.rs2]));
    write(1, ", ", 2);
    write(1, decimal, digits);
    write(1, "(", 1);
    write(1, regs_alias[encoding.rv_S.rs1], stringlen(regs_alias[encoding.rv_S.rs1]));
    write(1, ")", 1);
}

// inst rs1, rs2, offset
void print_fmt_rv_B(rv_inst encoding, const char *str)
{
    char decimal[DECIMAL_SIZE];
    struct {signed int x:12;} s;
    int num = s.x = ( (encoding.rv_B.imm12 << 11) | (encoding.rv_B.imm11 << 10) | (encoding.rv_B.imm10_5 << 4) | ( encoding.rv_B.imm4_1) )<<1;

    int digits = num_digits(num);
    if (num < 0)
        digits++;

    int_to_signed_dec_str(num, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_B.rs1], stringlen(regs_alias[encoding.rv_B.rs1]));
    write(1, ", ", 2);
    write(1, regs_alias[encoding.rv_B.rs2], stringlen(regs_alias[encoding.rv_B.rs2]));
    write(1, ", ", 2);
    write(1, decimal, digits);
}

void print_fmt_jal(rv_inst encoding, const char *str)
{
    char decimal[DECIMAL_SIZE];
    struct {signed int x:20;} s;
    int num = s.x = ( (encoding.rv_J.imm20 << 19) | (encoding.rv_J.imm19_12 << 11) | (encoding.rv_J.imm11 << 10) | (encoding.rv_J.imm10_1) )<<1;

    int digits = num_digits(num);
    if (num < 0)
        digits++;

    int_to_signed_dec_str(num, decimal);
    write(1,str, stringlen(str));
    write(1,"\t", 1);
    write(1, regs_alias[encoding.rv_J.rd], stringlen(regs_alias[encoding.rv_J.rd]));
    write(1, ", ", 2);
    write(1, decimal, digits);
}

enum rv_type get_instruction_type(rv_inst encoding)
{
    unsigned int opcode = encoding.rv_R.opcode;
    switch (opcode)
    {
        case 0x17:          // auipc
        case 0x37:          // lui
            return format_U;
        case 0x6f:          // jal
            return format_J;
        case 0x03:
        case 0x0f:
        case 0x13:
        case 0x67:          // jalr
        case 0x73:
            return format_I;
        case 0x63:
            return format_B;
        case 0x23:
            return format_S;
        case 0x33:
            return format_R;
        default:
            return Unknown;
    }
}

// Verifica se o endereço corresponde a algum simbolo, retorna o indice do simbolo ou -1
int is_symbol(off_t addr, const Elf32_Sym *sym_array, int n_symbols)
{
    int index = -1;    
    for (int i = 1; i < n_symbols; i++)
    {
        if (sym_array[i].st_value == addr)
            index = i;
    }

    return index;
}

void print_spaced_hex(unsigned int num)
{
    char hex[PADDED_HEX_SIZE+1];
    char little_hex[PADDED_HEX_SIZE+4];
    int_to_padded_hex(num, hex, PADDED_HEX_SIZE);
    change_hex_endian(hex, little_hex, PADDED_HEX_SIZE);

    for (int i = 0; i < PADDED_HEX_SIZE; i+= 2)
    {
        write(1, little_hex+i, 2);
        if (i != 6)
        {
            write(1, " ", 1);
        }
    }
}

void print_section_headers(const unsigned char *data, const char *filename, const Elf32_Ehdr file_header, Elf32_Shdr shstrtab_h)
{
    char ini_str[] = "\n";
    size_t filename_size = stringlen(filename);
    char ini_str2[] = ":\tfile format ELF32-riscv\n\nSections:\nIdx\tName\tSize\tVMA\n";
    write(1, ini_str, 1);
    write(1, filename, filename_size);
    write(1, ini_str2, stringlen(ini_str2));

    for (int i = 0; i < file_header.e_shnum; i++) 
    {
        Elf32_Shdr s_hdr = get_section_header(data, file_header, i);
        print_section_header(data, s_hdr, shstrtab_h, i);
        write(1, "\n",1);
    }
    write(1, "\n",1);
}

void print_section_header(const unsigned char *data, const Elf32_Shdr s_hdr, const Elf32_Shdr shstrtab_h, int index)
{
    char str_index[MAX_INDEX_DIGITS+1];
    int_to_unsigned_dec_str(index, str_index); // Assume 0 < index <= 99 
    write(1, str_index, stringlen(str_index));
    write(1, "\t", 1);

    print_section_name(data, s_hdr, shstrtab_h);
    write(1, "\t", 1);

    print_paddedhex(s_hdr.sh_size);
    write(1, "\t", 1);

    print_paddedhex(s_hdr.sh_addr);
}

void print_section_name(const unsigned char *data, const Elf32_Shdr s_hdr, const Elf32_Shdr shstrtab_h)
{
    off_t offset = shstrtab_h.sh_offset + s_hdr.sh_name;
    size_t name_len = stringlen((const char *) (data + offset));
    write(1, data+offset, name_len);
}

void print_symbol_table(const unsigned char *data, const char *filename, const Elf32_Ehdr file_header, const Elf32_Sym *sym_array, Elf32_Shdr shstrtab_h, const Elf32_Shdr strtab_h, const Elf32_Shdr symtab_h)
{
    char ini_str[] = "\n";
    size_t filename_size = stringlen(filename);
    char ini_str2[] = ":\tfile format ELF32-riscv\n\nSYMBOL TABLE:\n";
    write(1, ini_str, 1);
    write(1, filename, filename_size);
    write(1, ini_str2, stringlen(ini_str2));

    int n_symbols = symtab_h.sh_size / symtab_h.sh_entsize;

    for (int i = 1; i < n_symbols; i++)
    {
        print_symbol_entry(data, file_header, sym_array[i], strtab_h, shstrtab_h);
        write(1, "\n", 1);
    }
}

void print_symbol_entry(const unsigned char *data, const Elf32_Ehdr file_header, const Elf32_Sym symbol, const Elf32_Shdr strtab_h, const Elf32_Shdr shstrtab_h)
{
    print_paddedhex(symbol.st_value);
    write(1, "\t", 1);

    Elf32_Shdr s_hdr = get_section_header(data, file_header, symbol.st_shndx);
    print_section_name(data, s_hdr, shstrtab_h);
    write(1, "\t", 1);

    print_paddedhex(symbol.st_size);
    write(1, "\t", 1);

    print_symbol_name(data, symbol, strtab_h);
}

void print_symbol_name(const unsigned char *data, const Elf32_Sym symbol, const Elf32_Shdr strtab_h)
{
    off_t offset = strtab_h.sh_offset + symbol.st_name;
    size_t symbol_len = stringlen((const char *) (data + offset));
    write(1, data+offset, symbol_len);
}

// Retorna o sh_name associado ao nome passado ou -1 caso não encontre
Elf32_Word sh_name_from_name(const char *name, const unsigned char *data, const Elf32_Ehdr file_header, const Elf32_Shdr shstrtab_h)
{
    int i;
    const unsigned char *begin = data + shstrtab_h.sh_offset;
    Elf32_Word sh_name = 0;
    for (i = 0; i < file_header.e_shnum; i++)
    {
        size_t str_size = stringlen((const char *) (begin + sh_name)) + 1;
        if (stringcmp(name, (const char *) (begin + sh_name)))
            break;
        else 
        {
            sh_name += str_size;
        }
    }

    if (i == file_header.e_shnum)
        return -1;
    else
        return sh_name;
}

Elf32_Shdr Shdr_from_sh_name(const unsigned char *data, const Elf32_Ehdr file_header, Elf32_Word shname)
{
    Elf32_Shdr Shdr = { 0 };
    for (int i = 0; i < file_header.e_shnum; i++) 
    {
        Shdr = get_section_header(data, file_header, i);
        if (Shdr.sh_name == shname)
            return Shdr;
    }
    return Shdr;
}

Elf32_Shdr Shdr_from_section_name(const char *name, const unsigned char *data, const Elf32_Ehdr file_header, Elf32_Shdr shstrtab_h)
{
    Elf32_Word sh_name = sh_name_from_name(name, data, file_header, shstrtab_h);
    Elf32_Shdr Shdr = Shdr_from_sh_name(data, file_header, sh_name);
    return Shdr;
}

Elf32_Ehdr get_elf_header(const unsigned char *data)
{
    Elf32_Ehdr file_header;
    file_header.e_shoff     = (Elf32_Off)  array_of_bytes_to_uint(data, 32, 4);
    file_header.e_shentsize = (Elf32_Half) array_of_bytes_to_uint(data, 46, 2);
    file_header.e_shnum     = (Elf32_Half) array_of_bytes_to_uint(data, 48, 2);
    file_header.e_shstrndx  = (Elf32_Half) array_of_bytes_to_uint(data, 50, 2);

    return file_header;
}

Elf32_Shdr get_section_header(const unsigned char *data, const Elf32_Ehdr file_header, int index)
{
    Elf32_Shdr Shdr;
    off_t offset = (file_header.e_shoff) + (index * file_header.e_shentsize);

    Shdr.sh_name      = (Elf32_Word) array_of_bytes_to_uint(data, offset, 4);
    Shdr.sh_addr      = (Elf32_Addr) array_of_bytes_to_uint(data, offset+12, 4);
    Shdr.sh_offset    = (Elf32_Off)  array_of_bytes_to_uint(data, offset+16, 4);
    Shdr.sh_size      = (Elf32_Word) array_of_bytes_to_uint(data, offset+20, 4);
    Shdr.sh_entsize   = (Elf32_Word) array_of_bytes_to_uint(data, offset+36, 4);

    return Shdr;
}

void build_sym_array(const unsigned char *data, Elf32_Sym *sym_array, int n_symbols, Elf32_Shdr symtab_h)
{
    for (int i = 1; i < n_symbols; i++)
    {
        sym_array[i] = get_symbol_entry(data, symtab_h, i);
    }
}

Elf32_Sym get_symbol_entry(const unsigned char *data, Elf32_Shdr symbol_table_h, int index)
{
    Elf32_Sym symbol;
    off_t offset = symbol_table_h.sh_offset + (index * symbol_table_h.sh_entsize);

    symbol.st_name   = (Elf32_Word) array_of_bytes_to_uint(data, offset,    4);
    symbol.st_value  = (Elf32_Addr) array_of_bytes_to_uint(data, offset+4,  4);
    symbol.st_size   = (Elf32_Word) array_of_bytes_to_uint(data, offset+8,  4);
    symbol.st_shndx  = (Elf32_Half) array_of_bytes_to_uint(data, offset+14, 2);

    return symbol;
}

// Assume string termina com '\0'
size_t stringlen(const char *str)
{
    int i = 0;
    while(*str++ != '\0')
        i++;
    return i;
}

int stringcmp(const char *name, const char *ptr)
{
    while(*ptr != '\0')
    {
        if (*name++ != *ptr++)
            return 0;
    }
    if (*ptr == *name)
        return 1;
    else
        return 0;
}

void print_paddedhex(unsigned int num)
{
    char hex[PADDED_HEX_SIZE+1];
    int_to_padded_hex(num, hex, PADDED_HEX_SIZE);
    write(1, hex, PADDED_HEX_SIZE);
}

void print_hex(unsigned int num)
{
    int n = num_hex_digits(num);
    char hex[PADDED_HEX_SIZE + 1]; 
    int_to_hex(num, hex);
    write(1, hex, n);
}

// Assume uma representação little endian
unsigned int array_of_bytes_to_uint(const unsigned char *data, off_t offset, size_t size)
{
    unsigned int num = 0;
    for (size_t i = 0; i < size; i++)
    {
        num += data[offset+i] * my_pow(16, i*2);
    }
    return num;
}

void int_to_signed_dec_str(unsigned int num, char *str)
{
    int digit;
    if (num & (1U << 31))
    {
        num = (~num) + 1;
        str[0] = '-';

        int digits = num_digits(num);
        for (int i = digits; i >= 1; i--) 
        {
            digit = num %10;
            num = num/10;
            str[i] = digit + '0';
        }
        str[digits+1] = '\0';
    }
    else
    {
        int digits = num_digits(num);
        for (int i = digits-1; i >= 0; i--) 
        {
            digit = num %10;
            num = num/10;
            str[i] = digit + '0';
        }
        str[digits] = '\0';
    }
}

void int_to_unsigned_dec_str(unsigned int num, char *str)
{
    int digit;
    int digits = num_digits(num);

    for (int i = digits-1; i >=0; i--)
    {
        digit = num%10;
        num = num/10;
        str[i] = digit + '0';
    }
    str[digits] = '\0';
}

unsigned hex_to_uint(char *hex, int size_hex)
{
    unsigned int decimal = 0;
    int digit;

    for (int i = 2; i < size_hex; i++)
    {
        if (hex[i]>= '0' && hex[i] <= '9')
        {
            digit = (hex[i] - '0');
        }
        else if (hex[i] >= 'a' && hex[i] <='f') 
        {
            digit = (10 + (hex[i] - 'a'));
        }
        decimal += digit*my_pow(16, ((size_hex - 1) - 2) - (i-2));
    }
    return decimal;
}

void change_hex_endian(char *hex, char *big_hex, int size_hex)
{
    for(int i = 0, j = size_hex - 2; i < size_hex; i += 2, j -= 2 )
    {
        big_hex[i] = hex[j];
        big_hex[i+1] = hex[j+1];
    }
    big_hex[size_hex] = '\0';
}

void int_to_padded_hex(unsigned int decimal, char* hex, int size_hex)
{
    for (int i = size_hex -1; i >= 0; i -= 1 )
    {
        int digit = decimal % 16; 
        decimal = decimal / 16;
        if (digit >= 1 && digit <= 9)
            hex[i] = digit + '0';
        else if (digit >= 10 && digit <= 15)
        {
            digit = 'a' + (digit - 10);
            hex[i] = digit; 
        }
        else
            hex[i] = '0';
    }
    hex[size_hex] = '\0';
}

// Assume que hex é grande o bastante
void int_to_hex(unsigned int decimal, char *hex)
{
    int digit;
    int n_digits = num_hex_digits(decimal);

    for (int i = n_digits -1; i >= 0; i -= 1 )
    {
        digit = decimal % 16; 
        decimal = decimal / 16;
        if (digit >= 1 && digit <= 9)
            hex[i] = digit + '0';
        else if (digit >= 10 && digit <= 15)
        {
            digit = 'a' + (digit - 10);
            hex[i] = digit; 
        }
        else
            hex[i] = '0';
    }
    hex[n_digits] = '\0';
}

unsigned int my_pow(int base, int exp)
{
    int res = 1;
    for (int i = 0; i < exp; i++)
        res *= base;
    return res;
}

int num_digits(unsigned int n)
{
    if (n == 0) return 1;

    if (n & (1U << 31))
        n = ~n +1;

    int digit = 0;
    while(n != 0)
    {
        digit++;
        n = n/10;
    }
    return digit;
}

int num_hex_digits(unsigned int n)
{
    if (n == 0) return 1;
    else
    {
        int digit = 0;
        while (n != 0)
        {
            digit++;
            n = n/16;
        }
        return digit;
    }
}
