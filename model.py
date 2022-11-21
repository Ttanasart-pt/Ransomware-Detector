import torch
from assembly_extract import OPS_LENGTH

import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import global_mean_pool
from torch_geometric.nn import GATv2Conv

latent_dim = 32

class GAT(torch.nn.Module):
    def __init__(self, hidden_channels):
        super(GAT, self).__init__()
        self.conv1 = GATv2Conv(OPS_LENGTH, hidden_channels)
        self.conv2 = GATv2Conv(hidden_channels, hidden_channels)
        self.conv3 = GATv2Conv(hidden_channels, hidden_channels)
        self.lin = nn.Sequential(
            nn.Linear(hidden_channels, 128),
            nn.Sigmoid(),
            nn.Linear(128, 64),
            nn.Sigmoid(),
            nn.Linear(64, 2)
        ) 

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = x.relu()
        x = self.conv2(x, edge_index)
        x = x.relu()
        x = self.conv3(x, edge_index)
        
        x = global_mean_pool(x, batch)
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.lin(x)
        return x
    
def Model():
    WEIGHT_PATH = "weightGAT.pt"

    inference_model = GAT(hidden_channels = latent_dim)
    inference_model.load_state_dict(torch.load(WEIGHT_PATH))
    #inference_model.eval()
    
    return inference_model