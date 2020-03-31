import capstone as cs
import pefile

class ClassRefScanner:
    def __init__(self, pe, mode):
        if(type(pe) != pefile.PE):
            return
        self.pe = pe
        if mode == 32:
            self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        elif mode == 64:
            self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.mode = mode
        self.code_bytes = b''
        self.section_offset = 0
        for section in self.pe.sections:
            if section.Name == b'.text\x00\x00\x00':
                self.code_bytes = section.get_data()
                self.section_offset = section.PointerToRawData


    def find_bytes(self, bytes):
        index = 1
        results = []
        while index != -1:
            index = self.code_bytes.find(bytes, index)
            if index != -1:
                results.append(index)
                index += 1
        return results


    def disasm_code(self, offset, length):
        return self.md.disasm_lite(self.code_bytes[offset:offset+length], self.pe.OPTIONAL_HEADER.ImageBase)


    def get_class_references(self, vftable_va):
        #32bit bugged
        references = []
        if self.mode == 32:
            offsets = self.find_bytes(b'\xC7')
        elif self.mode == 64:
            return
        for offset in offsets:
            for (address, size, mnemonic, op_str) in self.disasm_code(offset, 6):
                if op_str.find(vftable_va) != -1:
                    rva = self.pe.get_rva_from_offset(offset+self.section_offset)
                    references.append((rva, mnemonic, op_str))
                    print((hex(rva),mnemonic, op_str))

        print("found", len(references), "references")
        return references


