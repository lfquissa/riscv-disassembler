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

