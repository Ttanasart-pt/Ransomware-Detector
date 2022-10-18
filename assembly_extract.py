from ctypes import addressof
from queue import Queue
import pefile
import os
from capstone import *
import argparse
import csv
from tqdm import tqdm

from block import block, codeBlock, dataBlock

OPS_LENGTH = 5

class Disassamble():
    BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
        "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz", "loop", "loopne",
        "loope", "call", "lcall"]
    BNC = ["jmp", "jmpf", "ljmp"]
    END = ["ret", "retn", "retf", "iret", "int3"]

    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.skipdata = True
        self.blocks = {}

        self.adjGraph = []

    def blockExist(self, addr):
        ar = list(self.blocks.keys())
        ar.sort()
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

                if(len(block) == OPS_LENGTH):
                    willBreak = True

            if willBreak:
                _block = self.blocks[asm.address] if asm.address in self.blocks\
                    else codeBlock(asm.address)
                self.blocks[asm.address] = _block
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
                
                if addr not in self.blocks:
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
            #print(f"Scanning section {section.Name}")
            #print(f"\tOffset: {section.VirtualAddress}")
            #print(f"\tSize: {section.SizeOfRawData}")
            
            if b'text' in section.Name:
                self.readTextSection(section)
            elif b'data' in section.Name:
                self.readDataSection(section)

        #print("Assembly extraction complete")
    
    def empty(self):
        for _, b in self.blocks.items():
            if not isinstance(b, codeBlock):
                continue
            if len(b) > 1:
                return False
        return True

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
                f.write(f"{b.writeOpcodes()}\n")

    def writeAdj(self, fname):
        with open(fname, "w") as f:
            writer = csv.writer(f)
            writer.writerows(self.adjGraph)

    def graphify(self):
        blockInd = {}

        for _, b in self.blocks.items():
            if not isinstance(b, codeBlock):
                continue
            b.ind = len(blockInd)
            blockInd[b.address] = b.ind
        
        for _, b in self.blocks.items():
            if not isinstance(b, codeBlock):
                continue
            fr = b.ind
            for t in b.target:
                if t not in blockInd:
                    continue
                self.adjGraph.append([fr, blockInd[t]])
    
folderIn, folderOut = "benign", "sampleb"
#folderIn, folderOut = "ransom", "sample"

def disasm(path):
    adj = os.path.basename(path)[:24].zfill(24)
    outfile = f"{folderIn}/{adj}.txt" if parse.o == None else parse.o
    opfile = f"{folderIn}/{adj} ops.txt"
    adjFile = f"{folderIn}/{adj} adj.txt"
    
    dism = Disassamble()
    dism.disassmble(path)

    dism.graphify()
    if dism.empty():
        return

    dism.write(outfile)
    dism.writeOpcode(opfile)
    dism.writeAdj(adjFile)

if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("-i")
    args.add_argument("-o")

    parse = args.parse_args()

    if parse.i == None: 
        for f in tqdm(os.listdir(folderOut)):
            disasm(folderOut + '/' + f)
    else:
        infile = parse.i
        disasm(infile)