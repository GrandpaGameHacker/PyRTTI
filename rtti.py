import pefile
import struct

from ctypes import *

from ctypes.wintypes import *

_UnDecorateSymbolName_ = \
    WinDLL('dbghelp.dll', use_last_error=True).UnDecorateSymbolName
_UnDecorateSymbolName_.argtypes = [LPCSTR, LPSTR, DWORD, DWORD]
_UnDecorateSymbolName_.restype = DWORD

MODE = {0x10b: 32, 0x20b: 64}

CompleteObjectLocator = struct.Struct("IIIII")


class RTTIScanner:
    def __init__(self, target):
        self.target = target
        self.pe = pefile.PE(self.target)
        self.data = self.pe.__data__.read()
        self.pe.__data__.seek(0)

        self.mode = MODE[self.pe.OPTIONAL_HEADER.Magic]
        self.s_qword = struct.Struct('Q')
        self.s_dword = struct.Struct('I')

        if self.mode == 32:
            print("32-bit file loaded")
            self.ptr_t = self.s_dword.size
            self.ptr_c = self.s_dword

        elif self.mode == 64:
            print("64-bit file loaded")
            self.ptr_t = self.s_qword.size
            self.ptr_c = self.s_qword

        self.symbols = list()
        self.objectLocators = list()
        self.vftables = list()

    def find_type_vftable(self):
        index = self.data.find(b'.?AVtype_info@@')
        if index != -1:
            index = index - (self.ptr_t * 2)
            return self.data[index:index + 8]
        else:
            print("ERROR: Data Not Found")
        return None


    def find_bytes(self, bytes):
        index = 1
        results = []
        while index != -1:
            index = self.data.find(bytes, index)
            if index != -1:
                results.append(index)
                index += 1
        return results


    def find_pattern(self, pattern, mask):
        patterns_found = []
        for i in range(len(self.data)):
            for x in range(len(mask)):
                if (self.data[i + x] == pattern[x]) or (mask[x] == 0x3F):
                    if x == len(mask) - 1:
                        patterns_found.append(i)
                else:
                    break
        return patterns_found

    def find_references(self, dwValue):
        results = []
        dwBytes = self.s_qword.pack(dwValue)
        index = 1
        while index != -1:
            index = self.data.find(dwBytes, index)
            if index != -1:
                results.append(index)
                index += 1
        return results

    def find_first_reference(self, dwValue):
        dwBytes = self.ptr_c.pack(dwValue)
        index = 1
        while index != -1:
            index = self.data.find(dwBytes, index)
            if index != -1:
                return index
                index += 1

    def UndecorateSymbol(self, symbol):
        modified_symbol = b'??_7' + symbol[4:] + b'6B@'
        bufferlen = 0x1000
        buffer = create_string_buffer(bufferlen)
        if _UnDecorateSymbolName_(modified_symbol, buffer, bufferlen, 0):
            modified_symbol = buffer.value.decode("ASCII")
            modified_symbol = modified_symbol.replace("const ", "")
            modified_symbol = modified_symbol.replace("::`vftable'", "")
            modified_symbol = modified_symbol.replace("`anonymous namespace'::", "")

            return modified_symbol
        else:
            print("UndecorateSymbol failed:\n", symbol)
            return symbol

    def __SCAN64__(self):
        print("scanning for type_info...")
        type_vftable_rva = self.s_qword.unpack(self.find_type_vftable())[0]
        type_vftable_rva = type_vftable_rva - self.pe.OPTIONAL_HEADER.ImageBase
        type_vftable_offset = self.pe.get_offset_from_rva(type_vftable_rva)

        type_meta_offset = type_vftable_offset - self.ptr_t
        type_meta_offset_data = \
            self.data[type_meta_offset:type_meta_offset + self.ptr_t]
        type_meta_offset = self.pe.get_offset_from_rva(
            self.ptr_c.unpack(type_meta_offset_data)[0]
            - self.pe.OPTIONAL_HEADER.ImageBase)

        type_meta_data = self.data[type_meta_offset:type_meta_offset + 24]
        print("type data:", type_meta_data)

        print("scanning for CompleteObjectLocator structs...")
        self.objectLocators = self.find_pattern(
            type_meta_data, b'xxxxxxxxxxxx???x???x')

        for objectLocator in self.objectLocators:
            sig, offset, cdOffset, pTypeDescriptorRVA, pClassDescriptorRVA = \
                CompleteObjectLocator.unpack(
                    self.data[objectLocator:objectLocator + CompleteObjectLocator.size])

            objectLocatorVA = self.pe.get_rva_from_offset(
                objectLocator) + self.pe.OPTIONAL_HEADER.ImageBase
            meta_vftable = self.find_first_reference(objectLocatorVA)
            if(meta_vftable != None):
                vftable = meta_vftable + self.ptr_t
                va_vftable = self.pe.OPTIONAL_HEADER.ImageBase + \
                    self.pe.get_rva_from_offset(vftable)
                symbol = self.pe.get_string_at_rva(
                    pTypeDescriptorRVA + self.ptr_t * 2)
                symbol = self.UndecorateSymbol(symbol)
                self.symbols.append(symbol)
                self.vftables.append(va_vftable)

    def __SCAN32__(self):
        # fuck this shit it wont work for now
        pass

    def scan(self):
        if self.mode == 32:
            self.__SCAN32__()
        elif self.mode == 64:
            self.__SCAN64__()
