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

    def __init__(self):
        super().__init__()
        self.byte_order = None  # 用于存储用户选择的字节序

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # 如果字节序尚未选择，则提示用户选择
        if not self.byte_order:
            self.byte_order = self.choose_byte_order()
            if not self.byte_order:
                print("No byte order selected. Exiting.")
                return

        print(f"Using byte order: {self.byte_order}")

        # 获取当前选中的地址范围
        selstart, selend = idc.read_selection_start(), idc.read_selection_end()
        if selstart == idc.BADADDR or selend == idc.BADADDR or selstart == selend:
            print("No valid selection or selection is empty.")
            return

        print(f"Selected address range: {hex(selstart)} - {hex(selend)}")

        selection = list(idautils.Heads(selstart, selend + 1))

        if not selection:
            print("No instructions or data in the selected range.")
            return

        print(f"Total selected items: {len(selection)}")

        for ea in selection:
            if ida_bytes.is_data(ida_bytes.get_flags(ea)):
                data = ida_bytes.get_bytes(ea, idc.get_item_size(ea))
                if data:
                    try:
                        # 根据用户选择的字节序解析指针值
                        pointer_value = int.from_bytes(data[:4], byteorder=self.byte_order)

                        # 获取指针指向的字符串
                        string_data = ida_bytes.get_bytes(pointer_value, 256)
                        string_data = string_data.split(b'\x00')[0]
                        string = string_data.decode('utf-8').strip()

                        if string:
                            print(f"Found string at {hex(ea)}: {string}")

                            if string.endswith(('.cgi', '.html', '.htm')):
                                func_name = self.generate_function_name(string)
                            else:
                                func_name = self.generate_function_name(string)

                            print(f"Generated function name: {func_name}")

                            # 查找与该字符串关联的函数地址
                            next_addr = self.get_function_address(ea + len(data))

                            if next_addr != idc.BADADDR:
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

    def choose_byte_order(self):
        # 插件运行时选择字节序
        choice = idc.ask_yn(1, "Use Little Endian byte order?\nSelect No for Big Endian.")
        if choice == 1:
            return 'little'
        elif choice == 0:
            return 'big'
        return None

    def generate_function_name(self, string):
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
        for ch in ";:[]/?!*|\\\"'<>.":
            str = str.replace(ch, '_')
        return str

    def get_function_address(self, ea):
        next_addr = idc.get_wide_dword(ea)
        if next_addr != idc.BADADDR:
            return next_addr
        return idc.BADADDR

    def rename_function(self, address, func_name):
        print(f"Renaming address {hex(address)} to {func_name}")
        if not idc.set_name(address, func_name, idaapi.SN_FORCE):
            print(f"Failed to rename {hex(address)}")
        else:
            print(f"Successfully renamed address {hex(address)} to function {func_name}")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return DCD_Recovery()
