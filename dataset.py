import os
from tqdm import tqdm

import torch
from torch_geometric.data import Data, data
from torch_geometric.data import InMemoryDataset

import csv
from process import OpcodeProcessor

op = OpcodeProcessor()

def convGraph(path, y):
    opfile  = f"{path} ops.txt"
    adjfile = f"{path} adj.txt"
    
    if not os.path.exists(opfile):
        return None
    if not os.path.exists(adjfile):
        return None
    
    sentences_raw = []
    with open(opfile, "r") as f:
        reader = csv.reader(f)
        for r in reader:
            sentences_raw.append(r)
    
    with open(adjfile, "r") as f:
        adj = f.read()
    adj = adj.split('\n')
    adjec_raw = []
    for a in adj:
        if a == '':
            continue
        sp = [int(s) for s in a.split(',')]
        adjec_raw.append(sp)
    
    op.sentencesRead(sentences_raw)
    
    x = op.sentenceIndex(sentences_raw).type(torch.float32)
    _y = torch.tensor([y]).type(torch.int64)
    edge = torch.tensor(adjec_raw).type(torch.int64).t().contiguous()
    
    data = Data(x = x, y = _y, edge_index = edge)
    return data

def readFile(path, y, amount = 5000):
    bn = 0
    for f in tqdm(os.listdir(path)):
        if f[:-7] == "adj.txt":
            continue
        if f[:-7] == "ops.txt":
            continue
        p = path + f[:-4]
        
        grap = convGraph(p, y)
        if not grap :
            continue
        if grap.x.shape[0] > 1:
            dataset.append(grap)
            bn += 1
            if bn > amount:
                break
    print(f"Converted {bn} files, dict size = {op.DICT_SIZE}")

if __name__ == "__main__":
    dataset = []
    
    readFile('data/training/16g/benign/', 0)
    readFile('data/training/16g/ransom/', 1)
    
    torch.save(dataset, "data/dataset16N.pt")
    op.saveDictionary('data/dict.json')