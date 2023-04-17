from assembly_extract import Disassamble

import torch
from torch_geometric.data import Data
from process import OpcodeProcessor

op = OpcodeProcessor()
op.loadDictionary('data/dict.json')

def disasm(path):
    dism = Disassamble()
    if not dism.disassmble(path):
        raise Exception("Error decompiling file: Disasembler return none")

    dism.graphify()
    
    if dism.empty():
        raise Exception("Error decompiling file: Empty result")

    ops = dism.getOpcode()
    adj = dism.getAdj()

    return (ops, adj)

def graphify(ops, adj):
    op.sentencesRead(ops)
    
    x = op.sentenceIndex(ops).type(torch.float32)
    edge = torch.tensor(adj).type(torch.int64).t().contiguous()
    
    data = Data(x = x, edge_index = edge)
    return data

def dismgrp(path):
    try:
        ops, adj = disasm(path)
        data = graphify(ops, adj)
    
        return data
    except Exception as e:
        raise e