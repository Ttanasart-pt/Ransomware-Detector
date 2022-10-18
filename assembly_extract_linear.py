from queue import Queue
import pefile
import os
import bisect
from capstone import *

BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
       "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz", "loop", "loopne",
       "loope", "call", "lcall"]
END = ["ret", "retn", "retf", "iret", "int3"]
BNC = ["jmp", "jmpf", "ljmp"]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.skipdata = True

def disassmble(infile, outfile):
    pe = pefile.PE(infile)
    assm = ""
    
    for section in pe.sections:
        print(f"Scanning section {section.Name}")
        
        if b'text' not in section.Name:
            continue

        addr = section.VirtualAddress
        code = section.get_data()
        
        disam = md.disasm(code, addr)
        for i in disam:
            assm += f"{hex(i.address)}\t{i.mnemonic}  \t{i.op_str}\n"

    with open(outfile, "w") as f:
        f.write(assm)

    print("Assembly extraction complete")

if __name__ == "__main__":
    infile = "sampleb/aitstatic.exe"
    outfile = f"dump.txt"
    
    disassmble(infile, outfile)