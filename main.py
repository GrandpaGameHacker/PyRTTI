import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import ntpath
import rtti


class PyClassInformer(tk.Frame):
    def __init__(self, root, *args, **kwargs):
        # root gui
        super(PyClassInformer, self).__init__()
        self.root = root
        self.root.title("PyClassInformer")
        self.root.geometry("400x300")
        self.mainloop = self.root.mainloop

        # menu
        self.menubar = tk.Menu(self.root)
        self.filemenu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=self.filemenu)
        self.filemenu.add_command(label="Open File", command=self.loadFile)
        self.filemenu.add_command(label="Export Data", command=self.exportData)
        self.root.config(menu=self.menubar)

        # controls
        self.lbl_file = tk.Label(text="TARGET*")

        self.scrollbar = tk.Scrollbar(self.root)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # classlist
        self.classlist = ttk.Treeview(self.root,
                                      yscrollcommand=self.scrollbar.set)
        self.classlist['columns'] = ('#1')
        self.classlist.heading("#0", text="vftable_addr", anchor=tk.W)
        self.classlist.heading("#1", text="symbol", anchor=tk.W)
        self.classlist.column("#0", width=150, minwidth=150, stretch=tk.YES)
        self.classlist.column("#1", width=270, minwidth=270, stretch=tk.YES)

        # gui style
        self.lbl_file.pack(anchor="w")
        self.classlist.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
        self.scrollbar.config(command=self.classlist.yview)
        # app variables
        self.file_path = None

    def loadFile(self):
        self.file_path = filedialog.askopenfilename(
            filetypes=(("Executable files", "*.exe"),
                       ("DLL Library", "*.dll"), ("all files", "*.*")))
        if self.file_path == '':
            print("Error - Invalid file path!")
            return
        self.lbl_file['text'] = ntpath.basename(self.file_path)
        self.update_idletasks()
        self.scanner = rtti.RTTIScanner(self.file_path)
        self.scanner.scan()
        for i in range(len(self.scanner.vftables)):
            self.classlist.insert("", i,
                                  text=str(hex(self.scanner.vftables[i])),
                                  values=(self.scanner.symbols[i].replace(" ", "\ ")))

    def exportData(self):
        pass


def main():
    app = PyClassInformer(tk.Tk())
    app.mainloop()


if __name__ == '__main__':
    main()
