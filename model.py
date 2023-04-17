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
        self.conv2 = GATv2Conv(hidden_channels, hidden_channels * 2)
        self.conv3 = GATv2Conv(hidden_channels * 2, hidden_channels)
        # self.lin = nn.Sequential(
        #     nn.Linear(hidden_channels, 128),
        #     nn.ReLU(),
        #     nn.Linear(128, 64),
        #     nn.ReLU(),
        #     nn.Linear(64, 2),
        #     nn.Sigmoid(),
        # ) 
        
        self.lin1 = nn.Linear(hidden_channels, 128)
        self.lin2 = nn.Linear(128, 64)
        self.lin3 = nn.Linear(64, 2)
        #self.lin3 = nn.Linear(64, 32)
        #self.lin4 = nn.Linear(32, 2)
        
        self.bng = nn.BatchNorm1d(hidden_channels)
        self.bn1 = nn.BatchNorm1d(128)
        self.bn2 = nn.BatchNorm1d(64)
        #self.bn3 = nn.BatchNorm1d(32)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = x.relu()
        x = self.conv2(x, edge_index)
        x = x.relu()
        x = self.conv3(x, edge_index)
        
        x = global_mean_pool(x, batch)
        
        x = F.dropout(x, p = 0.5, training = self.training)
        x = self.bng(x)
        
        print(f"x1 = {x.shape}")
        
        x = self.lin1(x)
        x = x.relu()
        x = self.bn1(x)
        
        #print(f"x2 = {x}")
        x = self.lin2(x)
        x = x.relu()
        x = self.bn2(x)
        
        #print(f"x3 = {x}")
        x = self.lin3(x)
        x = x.relu()
        #x = self.bn3(x)
        
        #print(f"x4 = {x}")
        #x = self.lin4(x)
        #x = x.relu()
        
        
        return x
    
def Model():
    WEIGHT_PATH = "data/weightGAT2.pt"

    inference_model = GAT(hidden_channels = latent_dim)
    inference_model.load_state_dict(torch.load(WEIGHT_PATH))
    inference_model.eval()
    
    return inference_model