import idc
import idaapi
import idautils

def calculate_address(qword_name, index, offset):
    # 获取 qword 的基地址
    qword_base = idc.get_name_ea_simple(qword_name)
    if qword_base == idc.BADADDR:
        print(f"Symbol {qword_name} not found")
        return None
    
    # 每个 qword 是 8 个字节，所以第 index 个元素的地址是基地址加上 index * 8
    qword_size = 8
    element_address = qword_base + (index * qword_size)
    
    # 再加上偏移量 offset
    final_address = element_address + offset
    
    return final_address

def main():
    # 输入部分，可以根据需要修改
    qword_name = "qword_5F45966130"  # 变量名
    index = 378                      # 数组索引
    offset = 4                       # 偏移量
    
    # 计算最终地址
    final_address = calculate_address(qword_name, index, offset)
    
    if final_address is not None:
        print(f"Address of (char *)&{qword_name}[{index}] + {offset}: 0x{final_address:X}")

if __name__ == "__main__":
    main()
