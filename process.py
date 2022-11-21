import torch
import json

class OpcodeProcessor():
    def __init__(self, op_len = 5) -> None:
        self.DICTIONARY = {
            "nop": 0
        }
        self.DICT_SIZE = 0
        
        self.sentences = None
        self.op_length = op_len

    def sentencesRead(self, sentences):
        self.sentences = sentences
        for sentence in sentences:
            for word in sentence:
                if word not in self.DICTIONARY:
                    self.DICTIONARY[word]= len(self.DICTIONARY)
        self.DICT_SIZE = len(self.DICTIONARY)

    def sentenceProcess(self, sentence):
        pad = self.op_length - len(sentence)
        return [0] * pad + [ self.DICTIONARY[word] for word in sentence ]

    def sentenceIndex(self, sentences):
        s = []
        for sentence in sentences:
            sent = self.sentenceProcess(sentence[:5])
            s.append(sent)
        return torch.tensor(s)
    
    def saveDictionary(self, path):
        with open(path, 'w') as f:
            f.write(json.dumps(self.DICTIONARY))