class block():
    def __init__(self, address) -> None:
        self.address = address
        self.ind = 0
        self.endAddr = address
        
class codeBlock(block):
    def __init__(self, address) -> None:
        super().__init__(address)
        self.target = []
        self.opcodes = []

    def append(self, assm):
        self.opcodes.append(assm)
        self.endAddr = max(self.endAddr, assm.address)
        
    def appendTarget(self, addr):
        self.target.append(addr)

    def split(self, addr):
        ind = 0
        b = None
        for i, op in enumerate(self.opcodes):
            if op.address < addr:
                continue
            if b is None:
                ind = i
                b = codeBlock(addr)
            b.append(op)
        if b is not None:
            b.target = [t for t in self.target]
            self.target.clear()
            self.appendTarget(b.address)
            self.opcodes = self.opcodes[:ind]
            self.endAddr = addr

        return b

    def __len__(self):
        return len(self.opcodes)

    def __str__(self) -> str:
        s = f"\n=== CODE BLOCK ADDRESS {hex(self.address)} ===\n"
        for i in self.opcodes:
            s += f"  {hex(i.address)}\t{i.mnemonic:5}  \t{i.op_str}\n"
        if self.target:
            s += f"  === BLOCK LINK ===\n"
            for i in self.target:
                s += f"    {hex(i)}\n"
        s += f"=== CODE BLOCK END ===\n"
        return s    
        
    def writeOpcodes(self) -> str:
        s = ''
        for i in self.opcodes:
            s += f"{i.mnemonic},"
        return s    

class dataBlock(block):
    def __init__(self, address, data) -> None:
        super().__init__(address)
        self.data = data

        self.endAddr = address + len(data)

    def __str__(self) -> str:
        s = f"\n=== DATA BLOCK ADDRESS {hex(self.address)} ===\n"
        addr = self.address

        linew = 16
        for i in range(0, len(self.data), linew):
            dat = self.data[i : i + linew]
            sb = ''
            st = ''
            for d in dat:
                byt = str(d.to_bytes(1, 'little'))
                byt = byt[2:]
                byt = byt[:-1]
                st += byt if byt[0] != "\\" else "0"
                sb += "0x{:02x}".format(d)[2:] + " "

            s += f"  {hex(addr)}\t{sb}\t{st}\n"
            addr += linew
        
        s += f"=== DATA BLOCK END ===\n"
        return s

    def __len__(self):
        return len(self.data)