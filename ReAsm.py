import idc
import idautils
import os


def search_code(start,end):
    ea = start
    file = open("code.cpp","w")
    str = "char c;\n"
    file.write(str)
    str = "string str;\n"
    file.write(str)
    while ea>=end:
        instr = idautils.DecodeInstruction(ea)
        insn_mnem = instr.get_canon_mnem()
        if insn_mnem == "cmp":
            value = idc.get_operand_value(ea,1)
            value = hex(value)
            str = "c = {};\n".format(value)
            
            file.write(str)
            
        elif insn_mnem == "ror":
            value = idc.get_operand_value(ea,1)
            value = hex(value)
            str = "c = _rotl8(c,{});\n".format(value)
            file.write(str)
        elif insn_mnem == "sub":
            value = idc.get_operand_value(ea,1)
            value = hex(value)
            str = "c = c + {};\n".format(value)
            file.write(str)
        elif insn_mnem == "add":
            operand = idc.print_operand(ea,0)
            if operand == 'rax':
                ea = idc.prev_head(ea)
                str = "str+=c;\n"
                file.write(str)
                continue
            else:
                value = idc.get_operand_value(ea,1)
                value = hex(value)
                str = "c = c - {};\n".format(value)
                file.write(str)
        elif insn_mnem == "rol":
            value = idc.get_operand_value(ea,1)
            value = hex(value)
            str = "c = _rotr8(c,{});\n".format(value)
            file.write(str)
        elif insn_mnem == "xor":
            value = idc.get_operand_value(ea,1)
            value = hex(value)
            str = "c = c ^ {};\n".format(value)
            file.write(str)
        if ea == end:
            str = "str+=c;\n"
            file.write(str)
        ea = idc.prev_head(ea)

    str ="std::reverse(str.begin(),str.end());\n"
    file.write(str)
    str = "std::cout << str << std::endl;\n"
    file.write(str)
    file.close()
    
    pass


def main():
    startEA = 0x7FFE4F1CD4CF
    endEA = 0x7FFE4F1CD28C
    search_code(startEA,endEA)

if __name__ == '__main__':
    main()