import pefile
import struct
import re
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
            self.ptr_t = self.s_dword.size
            self.ptr_c = self.s_dword

        elif self.mode == 64:
            self.ptr_t = self.s_qword.size
            self.ptr_c = self.s_qword
        self.rtti_found = False
        self.symbols = list()
        self.vftables_va = list()
        self.vftables_rva = list()
        self.vftables_offset = list()
        self.objectLocators = list()

    def find_type_vftable(self):
        index = self.data.find(b'.?AVtype_info@@')
        if index != -1:
            index = index - (self.ptr_t * 2)
            return self.data[index:index + 8]
        else:
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
                if (self.data[i + x] == pattern[x]) or (mask[x] == '?'):
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
            modified_symbol = modified_symbol.replace(
                "`anonymous namespace'::", "")

            return modified_symbol
        else:
            return symbol

    def __SCAN64__(self):
        type_vftable_data = self.find_type_vftable()
        if(type_vftable_data == None):
            return

        type_vftable_rva = self.s_qword.unpack(type_vftable_data)[0]
        type_vftable_rva = type_vftable_rva - self.pe.OPTIONAL_HEADER.ImageBase
        type_vftable_offset = self.pe.get_offset_from_rva(type_vftable_rva)

        type_meta_offset = type_vftable_offset - self.ptr_t
        type_meta_offset_data = \
            self.data[type_meta_offset:type_meta_offset + self.ptr_t]
        type_meta_offset = self.pe.get_offset_from_rva(
            self.ptr_c.unpack(type_meta_offset_data)[0]
            - self.pe.OPTIONAL_HEADER.ImageBase)

        type_meta_data = self.data[type_meta_offset:type_meta_offset + 24]

        self.objectLocators = self.find_pattern(
            type_meta_data, 'xxxxxxxxxxxx???x???x')
        if len(self.objectLocators) != 0:
            self.rtti_found = True
        for objectLocator in self.objectLocators:
            sig, offset, cdOffset, pTypeDescriptorRVA, pClassDescriptorRVA = \
                CompleteObjectLocator.unpack(
                    self.data[objectLocator:objectLocator + CompleteObjectLocator.size])

            objectLocatorVA = self.pe.get_rva_from_offset(
                objectLocator) + self.pe.OPTIONAL_HEADER.ImageBase
            meta_vftable = self.find_first_reference(objectLocatorVA)
            if(meta_vftable != None):
                vftable = meta_vftable + self.ptr_t
                rva_vftable = self.pe.get_rva_from_offset(vftable)
                va_vftable = self.pe.OPTIONAL_HEADER.ImageBase + rva_vftable
                    
                symbol = self.pe.get_string_at_rva(
                    pTypeDescriptorRVA + self.ptr_t * 2)
                symbol = self.UndecorateSymbol(symbol)
                self.symbols.append(symbol)
                self.vftables_offset.append(hex(vftable))
                self.vftables_rva.append(hex(rva_vftable))
                self.vftables_va.append(hex(va_vftable))


    def __SCAN32__(self):
        #NOTE TO SELF - BUGGED, doesnt always work
        type_vftable_data = self.find_type_vftable()
        if(type_vftable_data == None):
            return

        type_vftable_rva = self.s_qword.unpack(type_vftable_data)[0]
        type_vftable_rva = type_vftable_rva - self.pe.OPTIONAL_HEADER.ImageBase
        type_vftable_offset = self.pe.get_offset_from_rva(type_vftable_rva)

        type_meta_offset = type_vftable_offset - self.ptr_t
        type_meta_offset_data = \
            self.data[type_meta_offset:type_meta_offset + self.ptr_t]
        type_meta_offset = self.pe.get_offset_from_rva(
            self.ptr_c.unpack(type_meta_offset_data)[0]
            - self.pe.OPTIONAL_HEADER.ImageBase)

        type_meta_data = self.data[type_meta_offset:type_meta_offset + 24]

        specialByte = (type_meta_data[0xe] >> 4) << 4
        specialByte2 = specialByte + 0xF
        specialByte_str = specialByte.to_bytes(1, 'little')
        specialByte_str2 = specialByte2.to_bytes(1, 'little')
        
        self.pe.get_seself.data.find(b'.?AVtype_info@@')

        objectRegex = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00...[\xf0-\xff]...[\xf0-\xff]\x00\x00\x00\x00'
        objectRegex = objectRegex.replace(b'\xf0', specialByte_str)
        objectRegex = objectRegex.replace(b'\xff', specialByte_str2)

        objectDatas = re.findall(objectRegex, self.data)
        for objectData in objectDatas:
            index = self.data.find(objectData)
            self.objectLocators.append(index+1)
        if len(self.objectLocators) != 0:
            self.rtti_found = True

        for objectLocator in self.objectLocators:
            sig, offset, cdOffset, pTypeDescriptorVA, pClassDescriptorVA = \
                CompleteObjectLocator.unpack(
                    self.data[objectLocator:objectLocator + CompleteObjectLocator.size])
            objectLocatorVA = self.pe.get_rva_from_offset(objectLocator) + self.pe.OPTIONAL_HEADER.ImageBase
            meta_vftable = self.find_first_reference(objectLocatorVA)
            if(meta_vftable != None):
                vftable = meta_vftable + self.ptr_t
                rva_vftable = self.pe.get_rva_from_offset(vftable)
                va_vftable = self.pe.OPTIONAL_HEADER.ImageBase + rva_vftable
                symbol = self.pe.get_string_at_rva(pTypeDescriptorVA - self.pe.OPTIONAL_HEADER.ImageBase + self.ptr_t * 2)
                symbol = self.UndecorateSymbol(symbol)
                self.symbols.append(symbol)
                self.vftables_offset.append(hex(vftable))
                self.vftables_rva.append(hex(rva_vftable))
                self.vftables_va.append(hex(va_vftable))
#2BF540
    def scan(self):
        if self.mode == 32:
            self.__SCAN32__()
        elif self.mode == 64:
            self.__SCAN64__()
