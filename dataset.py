import os
from tqdm import tqdm

import torch
from torch_geometric.data import Data

import csv
from process import OpcodeProcessor

def convGraph(path, y):
    opfile  = f"{path} ops.txt"
    adjfile = f"{path} adj.txt"
    
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
    
    op = OpcodeProcessor()
    op.sentencesRead(sentences_raw)
    
    x = op.sentenceIndex(sentences_raw)
    y = torch.tensor([y])
    edge = torch.tensor(adjec_raw).t().contiguous()
    
    data = Data(x = x, y = y, edge_index = edge)
    return data

if __name__ == "__main__":
    dataset = []
    
    for f in tqdm(os.listdir('ransom')):
        if len(f) > 24 + 4:
            continue
        path = 'ransom/' + f[:-4]
        dataset.append(convGraph(path, 1))
    
    torch.save(dataset, "dataset.pt")