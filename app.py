import tkinter as tk
from tkinter import ttk
import sv_ttk
from tkinterdnd2 import DND_FILES, TkinterDnD

class RADAR(ttk.Frame):
    def __init__(self, parent):
        ttk.Frame.__init__(self)
        self.root = parent
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.onFileDrop)
        
        ttk.Label(self, text = "Drag file to analyze")\
            .place(relx = 0.5, rely = 0.5, anchor = tk.CENTER)
            
        self.resLabel = ttk.Label(self, text = "No file")
        self.resLabel.place(relx = 0.5, rely = 1, anchor = tk.S)
        
        self.fileDrop = None
        
    def onFileDrop(self, e):
        self.fileDrop = e.data
        self.resLabel.config(text = "File dropped " + e.data)

if __name__ == "__main__":
    print("Opening application...")
    
    root = TkinterDnD.Tk()
    root.title("RADAR")
    root.geometry("320x320")
    
    sv_ttk.set_theme("dark")
    app = RADAR(root)
    app.pack(fill = "both", expand = True, padx = 24, pady = 24)
    
    root.mainloop()