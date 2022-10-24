import torch
from model import GCN
from config import *
from dismgrp import dismgrp

new_model = GCN(hidden_channels = latent_dim)
new_model.load_state_dict(torch.load(WEIGHT_PATH))
new_model.eval()

def inference(path):
    data = dismgrp(path)
    res = new_model(data.x, data.edge_index, data.batch)  
    
    print(res)