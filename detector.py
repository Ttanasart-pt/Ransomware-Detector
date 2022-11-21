import torch
from dismgrp import dismgrp
from torch.nn.functional import softmax

def isRansom(model, path):
    try:
        data = dismgrp(path)
    except Exception as e:
        raise e
    
    res = model(data.x, data.edge_index, data.batch)[0]
    
    pre = torch.argmax(res).item()
    sm = softmax(res, dim = 0)
    prob = sm[pre].item() * 100
    return pre, prob