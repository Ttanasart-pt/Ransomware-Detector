from queue import Queue
import pefile
import os
import bisect
from capstone import *

from block import codeBlock, dataBlock

BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
       "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz", "loop", "loopne",
       "loope", "call", "lcall"]
END = ["ret", "retn", "retf", "iret", "int3"]
BNC = ["jmp", "jmpf", "ljmp"]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.skipdata = True

blocks = {}

def readTextSection(section):
    addrs = []
    addr = section.VirtualAddress
    code = section.get_data()
    
    queue = Queue()
    block = codeBlock(blocks, addr)
    disam = md.disasm(code, addr)
    _asm = None
    willBreak = False

    for asm in disam:
        if _asm is not None:
            block.append(_asm)
        if willBreak:
            _block = codeBlock(blocks, asm.address)
            block.appendTarget(asm.address)
            block = _block
            willBreak = False

        if(asm.mnemonic in BCC):
            try:
                queue.put((block, int(asm.op_str, 16)))
            except Exception:
                pass
            willBreak = True
        elif(asm.mnemonic in BNC):
            try:
                queue.put((block, int(asm.op_str, 16)))
            except Exception:
                pass
            willBreak = True
        elif(asm.mnemonic in END):
            if(queue.empty()):
                break
            frm, addr  = queue.get()
            disam = md.disasm(code, addr)
            block = codeBlock(blocks, addr)
            frm.appendTarget(addr)

        _asm = asm

def readDataSection(section):
    addr = section.VirtualAddress
    code = section.get_data()
    
    block = dataBlock(blocks, addr, code)

def disassmble(infile, outfile):
    pe = pefile.PE(infile)
    
    for section in pe.sections:
        print(f"Scanning section {section.Name}")
        #print(f"\tOffset: {section.VirtualAddress}")
        #print(f"\tSize: {section.SizeOfRawData}")
        
        if b'text' in section.Name:
            readTextSection(section)
        elif b'data' in section.Name:
            readDataSection(section)

    with open(outfile, "w") as f:
        f.write("===== Assembly blocks =====\n")
        for _, b in blocks.items():
            f.write(str(b))

    print("Assembly extraction complete")

if __name__ == "__main__":
    infile = "sample/VirusShare_711597ee812105d3ea6600bb0be7a25a"
    #infile = "sample/VirusShare_e1831d608e91f8eda9633ab698d90513"
    outfile = f"assembly/{os.path.basename(infile)}.txt"
    
    disassmble(infile, outfile)