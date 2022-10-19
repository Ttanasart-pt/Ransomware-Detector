from genericpath import exists
import os
from tqdm import tqdm

import torch
from torch_geometric.data import Data, data
from torch_geometric.data import InMemoryDataset

import csv
from process import OpcodeProcessor

OPS_LENGTH = 5

def exeGraph():
    return torch.load('data/dataset.pt')

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
    
    op = OpcodeProcessor(OPS_LENGTH)
    op.sentencesRead(sentences_raw)
    
    x = op.sentenceIndex(sentences_raw).type(torch.float32)
    _y = torch.tensor([y]).type(torch.int64)
    edge = torch.tensor(adjec_raw).type(torch.int64).t().contiguous()
    
    data = Data(x = x, y = _y, edge_index = edge)
    return data

if __name__ == "__main__":
    dataset = []
    
    bn = 0
    for f in tqdm(os.listdir('data/benign')):
        if len(f) > 24 + 4:
            continue
        path = 'data/benign/' + f[:-4]
        
        grap = convGraph(path, 0)
        if not grap :
            continue
        if grap.x.shape[0] > 1:
            dataset.append(grap)
            bn += 1
    print(f"Converted {bn} benign files.")
    
    rs = 0
    for f in tqdm(os.listdir('data/ransom')):
        if len(f) > 24 + 4:
            continue
        path = 'data/ransom/' + f[:-4]
        
        grap = convGraph(path, 1)
        if not grap :
            continue
        if grap.x.shape[0] > 1:
            dataset.append(grap)
            rs += 1
    print(f"Converted {rs} ransomware files.")
    
    torch.save(dataset, "data/dataset.pt")