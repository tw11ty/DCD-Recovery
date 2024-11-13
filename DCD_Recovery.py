import ida_bytes
import idautils
import idaapi
import idc

class DCD_Recovery(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "DCD Recovery Plugin for restoring function names from constants"
    help = "This plugin helps to recover function names from constant data in .data section."
    wanted_name = "DCD Recovery"
    wanted_hotkey = "Shift+R"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # 获取当前选中的地址范围
        selstart, selend = idc.read_selection_start(), idc.read_selection_end()
        if selstart == idc.BADADDR or selend == idc.BADADDR or selstart == selend:  # 无效的地址范围
            print("No valid selection or selection is empty.")
            return

        print(f"Selected address range: {hex(selstart)} - {hex(selend)}")

        selection = list(idautils.Heads(selstart, selend + 1))  # 获取选中的地址范围

        if not selection:
            print("No instructions or data in the selected range.")
            return

        print(f"Total selected items: {len(selection)}")
        
        for ea in selection:
            if ida_bytes.is_data(ida_bytes.get_flags(ea)):
                data = ida_bytes.get_bytes(ea, idc.get_item_size(ea))
                if data:
                    try:
#********************************************* 按情况处理指针指向的字符串 *********************************************
                        pointer_value = int.from_bytes(data[:4], byteorder='little')  # 默认小端序，取前4字节作为指针值

                        # 获取指针指向的字符串
                        string_data = ida_bytes.get_bytes(pointer_value, 256)  # 获取指针指向的字符串 
                        string_data = string_data.split(b'\x00')[0]  # 截断
                        string = string_data.decode('utf-8').strip()

                        if string:
                            print(f"Found string at {hex(ea)}: {string} ")  # 这里去掉了单引号，避免多余的引号

                            # print(f"String suffix: {string[-4:]}") 
                            # 检查后缀是否为.cgi、.html或.htm
#********************************************* 内容可以根据情况修改 *********************************************
                            if string.endswith('.cgi') or string.endswith('.html') or string.endswith('.htm'):
                                # 根据文件后缀处理
                                func_name = self.generate_function_name(string)
                            else:
                                print(f"Skipping non-cgi/htm/html string at {hex(ea)}: {string}")
                                func_name = self.generate_function_name(string)
                                
                            print(f"Generated function name: {func_name}")
                            # 查找与该字符串关联的函数地址
                            next_addr = self.get_function_address(ea + len(data))  # 查找字符串后的函数地址

                            if next_addr != idc.BADADDR:
                                # 如果找到了有效的函数地址，重命名该函数
                                print(f"Renaming function at address: {hex(next_addr)}")
                                self.rename_function(next_addr, func_name)
                            else:
                                print(f"No valid function found at address {hex(ea)}")
                    except Exception as e:
                        print(f"Error processing address {hex(ea)}: {e}")
                else:
                    print(f"No data at address {hex(ea)}")
            else:
                print(f"Address {hex(ea)} is not a data item.")

    def generate_function_name(self, string):
        # 根据文件后缀处理函数名称
        if string.endswith('.cgi'):
            base_name = string[:-4]
            return f"{self.str_replace(base_name)}CGI"
        elif string.endswith('.htm'):
            base_name = string[:-4]
            return f"{self.str_replace(base_name)}HTM"
        elif string.endswith('.html'):
            base_name = string[:-5]
            return f"{self.str_replace(base_name)}HTML"
        else:
            return self.str_replace(string.upper())   

    def str_replace(self, str):
        # 替换字符串中可能会出现的 ; : [ ] / ? ! * 等特殊字符
        str = str.replace(';', '_')
        str = str.replace(':', '_')
        str = str.replace('[', '_')
        str = str.replace(']', '_')
        str = str.replace('/', '_')
        str = str.replace('?', '_')
        str = str.replace('!', '_')
        str = str.replace('*', '_')
        str = str.replace('|', '_')
        str = str.replace('\\', '_')
        str = str.replace('"', '_')
        str = str.replace('\'', '_')
        str = str.replace('<', '_')
        str = str.replace('>', '_')
        str = str.replace('.', '_')
        return str

    def get_function_address(self, ea):
        next_addr = idc.get_wide_dword(ea)
        if next_addr != idc.BADADDR:
            return next_addr
        return idc.BADADDR

    def rename_function(self, address, func_name):
        # 如果地址已经是函数地址，则跳过
        print(f"Renaming address {hex(address)} to {func_name}")
        if not idc.set_name(address, func_name, idaapi.SN_FORCE):
            print(f"Failed to rename {hex(address)}")
        else:
            print(f"Successfully renamed address {hex(address)} to function {func_name}")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return DCD_Recovery()
