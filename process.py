import torch

class OpcodeProcessor():
    def __init__(self) -> None:
        self.DICTIONARY = {}
        self.DICT_SIZE = 0
        
        self.sentences = None
        self.max_length = 0

    def sentencesRead(self, sentences):
        self.sentences = sentences
        for sentence in sentences:
            for word in sentence:
                if word not in self.DICTIONARY:
                    self.DICTIONARY[word]= len(self.DICTIONARY)
            self.max_length = max(self.max_length, len(sentence))
        self.DICT_SIZE = len(self.DICTIONARY)
        print("Sentence read complete")

    def sentenceProcess(self, sentence):
        pad = self.max_length - len(sentence)
        return [ self.DICTIONARY[word] for word in sentence ] + [0] * pad

    def sentenceIndex(self, sentences):
        s = []
        for sentence in sentences:
            s.append(self.sentenceProcess(sentence))
        return torch.tensor(s)