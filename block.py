class block():
    def __init__(self, blocks, address) -> None:
        blocks[address] = self
        self.address = address

class codeBlock(block):
    def __init__(self, blocks, address) -> None:
        super().__init__(blocks, address)
        self.target = []
        self.opcodes = []

    def append(self, assm):
        self.opcodes.append(assm)
        
    def appendTarget(self, addr):
        self.target.append(addr)

    def __len__(self):
        return len(self.opcodes)

    def __str__(self) -> str:
        s = f"\n=== CODE BLOCK ADDRESS {hex(self.address)} ===\n"
        for i in self.opcodes:
            s += f"  {hex(i.address)}\t{i.mnemonic}  \t{i.op_str}\n"
        if self.target:
            s += f"  === BLOCK LINK ===\n"
            for i in self.target:
                s += f"    {hex(i)}\n"
        s += f"=== CODE BLOCK END ===\n"
        return s

class dataBlock(block):
    def __init__(self, blocks, address, data) -> None:
        super().__init__(blocks, address)
        self.data = data

    def __str__(self) -> str:
        s = f"\n=== DATA BLOCK ADDRESS {hex(self.address)} ===\n"
        s += f"  {hex(self.address)}\t{self.data}\n"
        s += f"=== DATA BLOCK END ===\n"
        return s