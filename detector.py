import torch
from dismgrp import dismgrp

def isRansom(model, path):
    try:
        data = dismgrp(path)
    except Exception as e:
        raise e
    
    res = model(data.x, data.edge_index, data.batch)[0]
    
    pre = torch.argmax(res).item()
    prob = res[pre].item() * 100
    return pre, prob