from assembly_extract import OPS_LENGTH
import torch
import json

class OpcodeProcessor():
    def __init__(self) -> None:
        self.DICTIONARY = {
            "nop": 0
        }
        self.DICT_SIZE = 0
        
        self.sentences = None

    def sentencesRead(self, sentences):
        self.sentences = sentences
        for sentence in sentences:
            for word in sentence:
                if word not in self.DICTIONARY:
                    print(f'{word} is not in dict')
                    self.DICTIONARY[word] = len(self.DICTIONARY)
        self.DICT_SIZE = len(self.DICTIONARY)

    def sentenceProcess(self, sentence):
        pad = OPS_LENGTH - len(sentence)
        return [0] * pad + [ self.DICTIONARY[word] for word in sentence ]

    def sentenceIndex(self, sentences):
        s = []
        for sentence in sentences:
            sent = self.sentenceProcess(sentence[:OPS_LENGTH])
            s.append(sent)
        return torch.tensor(s)
    
    def saveDictionary(self, path):
        with open(path, 'w') as f:
            f.write(json.dumps(self.DICTIONARY))
            
    def loadDictionary(self, path):
        f = open(path)
        self.DICTIONARY = json.load(f)