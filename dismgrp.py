from assembly_extract import Disassamble, OPS_LENGTH

import torch
from torch_geometric.data import Data
from process import OpcodeProcessor

def disasm(path):
    dism = Disassamble()
    if not dism.disassmble(path):
        return None

    dism.graphify()
    
    if dism.empty():
        return None

    ops = dism.getOpcode()
    adj = dism.getAdj()

    return (ops, adj)

def graphify(ops, adj):
    op = OpcodeProcessor(OPS_LENGTH)
    op.sentencesRead(ops)
    
    x = op.sentenceIndex(ops).type(torch.float32)
    edge = torch.tensor(adj).type(torch.int64).t().contiguous()
    
    data = Data(x = x, edge_index = edge)
    return data

def dismgrp(path):
    ops, adj = disasm(path)
    data = graphify(ops, adj)
    
    return data