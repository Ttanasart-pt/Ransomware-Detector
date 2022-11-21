import tkinter as tk
from tkinter import ttk
import sv_ttk
from tkinterdnd2 import DND_FILES, TkinterDnD

from model import Model
from detector import isRansom

import os
import threading

class RADAR(ttk.Frame):
    def __init__(self, parent):
        ttk.Frame.__init__(self)
        self.root = parent
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.onFileDrop)
        
        ttk.Label(self, text = "Drag file to analyze")\
            .place(relx = 0.5, rely = 0.4, anchor = tk.CENTER)
            
        self.fileLabel = ttk.Label(self, text = "No file")
        self.fileLabel.place(relx = 0.5, rely = 0.9, anchor = tk.S)
        
        self.resLabel = ttk.Label(self, text = "-")
        self.resLabel.place(relx = 0.5, rely = 1, anchor = tk.S)
        
        self.fileDrop = None
        
        self.model = Model()
        self.detectionThread = None
        
    def ransomDetect(self):
        try:
            res = isRansom(self.model, self.fileDrop)
            self.onFileAnalzed(res)
        except Exception as e:
            self.resLabel.config(text = f"{e}")
        
    def onFileDrop(self, e):
        path = e.data.lstrip('{').rstrip('}')
        self.fileDrop = path
        
        fname = os.path.basename(path)
        self.fileLabel.config(text = fname)
        self.resLabel.config(text = "Analyzing")
        
        self.detectionThread = threading.Thread(target = self.ransomDetect)
        self.detectionThread.start()
        
    def onFileAnalzed(self, results):
        pre, prob = results
        res = "Ransom" if pre == 1 else "Safe"
        result = f"{prob:.0f}% {res}"
        
        self.resLabel.config(text = result)

if __name__ == "__main__":
    print("Opening application...")
    
    root = TkinterDnD.Tk()
    root.title("RADAR")
    root.geometry("320x320")
    
    sv_ttk.set_theme("dark")
    app = RADAR(root)
    app.pack(fill = "both", expand = True, padx = 24, pady = 24)
    
    root.mainloop()