from ctypes import addressof
from queue import Queue
import pefile
import os
from capstone import *
import argparse

from block import codeBlock, dataBlock

class Disassamble():
    BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
        "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz", "loop", "loopne",
        "loope", "call", "lcall"]
    END = ["ret", "retn", "retf", "iret", "int3"]
    BNC = ["jmp", "jmpf", "ljmp"]

    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.skipdata = True
        self.blocks = {}

    def blockExist(self, addr):
        ar = list(self.blocks.keys())
        st = 0
        ed = len(ar) - 1

        lastBlock  = self.blocks[ar[-1]]
        if lastBlock.endAddr < addr:
            return None

        while ed - st > 1:
            md = round((st + ed) / 2)
            if ar[md] == addr:
                return self.blocks[ar[md]]
            elif ar[md] > addr:
                ed = md
            else:
                st = md
        return self.blocks[ar[st]]

    def readTextSection(self, section):
        addr = section.VirtualAddress
        code = section.get_data()
        
        queue = Queue()
        block = codeBlock(addr)
        self.blocks[addr] = block
        disam = self.md.disasm(code, addr)
        _asm = None
        willBreak = False

        for asm in disam:
            if _asm:
                block.append(_asm)
            if willBreak:
                _block = codeBlock(asm.address)
                self.blocks[addr] = _block
                block.appendTarget(asm.address)
                block = _block
                willBreak = False

            if(asm.mnemonic in self.BCC):
                try:
                    queue.put((block, int(asm.op_str, 16)))
                except Exception:
                    pass
                willBreak = True
            elif(asm.mnemonic in self.BNC):
                try:
                    queue.put((block, int(asm.op_str, 16)))
                except Exception:
                    pass
                willBreak = True
            elif(asm.mnemonic in self.END):
                if(queue.empty()):
                    break
                frm, addr  = queue.get()
                disam = self.md.disasm(code, addr)

                b = self.blockExist(addr)
                if b and b.address < addr < b.endAddr:
                    self.blocks[addr] = b.split(addr)
                else:
                    self.blocks[addr] = codeBlock(addr)
                frm.appendTarget(addr)
            _asm = asm

    def readDataSection(self, section):
        addr = section.VirtualAddress
        code = section.get_data()
        
        self.blocks[addr] = dataBlock(addr, code)

    def disassmble(self, infile):
        pe = pefile.PE(infile)
        
        for section in pe.sections:
            print(f"Scanning section {section.Name}")
            #print(f"\tOffset: {section.VirtualAddress}")
            #print(f"\tSize: {section.SizeOfRawData}")
            
            if b'text' in section.Name:
                self.readTextSection(section)
            elif b'data' in section.Name:
                self.readDataSection(section)

        print("Assembly extraction complete")
    
    def write(self, fname):
        with open(fname, "w") as f:
            f.write("===== Assembly blocks =====\n")
            for _, b in self.blocks.items():
                f.write(str(b))

    def writeOpcode(self, fname):
        with open(fname, "w") as f:
            for _, b in self.blocks.items():
                if not isinstance(b, codeBlock):
                    continue
                f.write(b.writeOpcodes() + "\n")


if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("-i")
    args.add_argument("-o")

    parse = args.parse_args()
    infile = "sample/VirusShare_711597ee812105d3ea6600bb0be7a25a" if parse.i == None else parse.i
    #infile = "sample/VirusShare_e1831d608e91f8eda9633ab698d90513"
    outfile = f"assembly/{os.path.basename(infile)}.txt" if parse.o == None else parse.o
    opfile = f"assembly/{os.path.basename(infile)} ops.txt"
    
    dism = Disassamble()
    dism.disassmble(infile)
    dism.write(outfile)
    dism.writeOpcode(opfile)