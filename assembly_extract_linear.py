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
    addrs = []
    idx = 0
    assm = ""

    def branch(addr):
        if(addr in addrs):
            return
        bisect.insort_left(addrs, addr)

    for section in pe.sections:
        print(f"Scanning section {section.Name}")
        #print(f"\tOffset: {section.VirtualAddress}")
        #print(f"\tSize: {section.SizeOfRawData}")
        
        if b'text' not in section.Name:
            continue

        addr = section.VirtualAddress
        code = section.get_data()
        
        queue = Queue()
        branch(addr)
        
        disam = md.disasm(code, addr)
        for i in disam:
            assm += f"{hex(i.address)}\t{i.mnemonic}  \t{i.op_str}\n"

    with open(outfile, "w") as f:
        f.write(assm)

    print("Assembly extraction complete")

if __name__ == "__main__":
    infile = "sample/VirusShare_711597ee812105d3ea6600bb0be7a25a"
    #infile = "sample/VirusShare_e1831d608e91f8eda9633ab698d90513"
    outfile = f"assembly/{os.path.basename(infile)} lin.txt"
    
    disassmble(infile, outfile)