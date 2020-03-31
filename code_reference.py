import capstone as cs
import pefile


MOV32_START_BYTE = b'\xC7' # reg/[addr]
MOV32_MAX_SIZE = 10

LEA64_START_BYTES = b'\x48\x8D' #48 8D reg/[reladdr]
LEA64_MAX_SIZE = 8

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
        return self.md.disasm_lite(
            self.code_bytes[offset:offset + length],
            self.pe.OPTIONAL_HEADER.ImageBase)

    def get_references_32(self, vftable_va):
        references = []
        offsets = self.find_bytes(MOV32_START_BYTE)
        for offset in offsets:
            for (address, size, mnemonic, op_str) in self.disasm_code(offset, MOV32_MAX_SIZE):
                if op_str.find(vftable_va) != -1:
                    rva = self.pe.get_rva_from_offset(
                    offset + self.section_offset)
                    references.append((rva, mnemonic, op_str))
                    print((hex(rva),size, mnemonic, op_str))
        return references

    # vftables in 64bit are commonly accessed with instruction LEA
    # Okay, so LEA64 is rip-relative addressed like
    # lea, rcx, [rip + 0x3600d]
    # that means we need to check if it adds or subtracts
    # then do the same to the rip of the instruction
    # to get the actual address, and then we compare that to vftable
    # if it mactches, log!
    def get_references_64(self, vftable_va):
        offsets = self.find_bytes(LEA64_START_BYTES)
        for offset in offsets:
            for (address, size, mnemonic, op_str) in self.disasm_code(offset, LEA64_MAX_SIZE):
                rva = self.pe.get_rva_from_offset(offset + self.section_offset)
                print((hex(rva),size, mnemonic, op_str))
                if op_str.find(vftable_va) != -1:
                    references.append((rva, mnemonic, op_str))

    def get_class_references(self, vftable_va):
        if self.mode == 32:
            return self.get_references_32(vftable_va)
        elif self.mode == 64:
            return self.get_references_64(vftable_va)


        print("found", len(references), "references")
        return references
