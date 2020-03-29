import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import ntpath
import rtti

class ClassViewer(ttk.Treeview):
    def __init__(self, parent, *args, **kwargs):
        ttk.Treeview.__init__(self, parent, *args, **kwargs)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy Selected", command=self.copy_selected)
        self.context_menu.add_command(label="Find Code References...",
                                      command=self.find_references)
        self.bind("<Button-3>", self.popup)


    def popup(self, event):
        try:
            self.context_menu.tk_popup(event.x_root+73, event.y_root+10, 0)
        finally:
            self.context_menu.grab_release()


    def to_str(self):
        text = ""
        item = self.get_children('')
        for i in item:
            text += ' | '.join(self.item(i, 'values'))
            text += "\n"
        return text


    def copy_selected(self):
        self.clipboard_clear()
        text = ""
        item = self.selection()
        for i in item:
            text += ' | '.join(self.item(i, 'values'))
            text += "\n"
        self.clipboard_append(text)

    def find_references(self):
        pass

    def sort_column(self, tv, col, reverse):
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        l.sort(reverse=reverse)

        # rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        # reverse sort next time
        tv.heading(col, command=lambda: \
                   self.sort_column(tv, col, not reverse))


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
        self.lbl_file = tk.Label(text="No File Selected.")
        self.xscrollbar = tk.Scrollbar(self.root, orient='horizontal')
        self.yscrollbar = tk.Scrollbar(self.root)
        self.xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.yscrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # classlist control
        self.classlist = ClassViewer(self.root,
                                      yscrollcommand=self.yscrollbar.set,
                                      xscrollcommand=self.xscrollbar.set)
        self.classlist['columns'] = ('#1','#2')
        for col in self.classlist['columns']:
            self.classlist.heading(col, text=col, command=lambda _col=col: \
                     self.classlist.sort_column(self.classlist, _col, True))

        self.classlist.heading("#0", text="ID", anchor=tk.W)
        self.classlist.heading("#1", text="VFTable VA", anchor=tk.W)
        self.classlist.heading("#2", text="Class", anchor=tk.W)
        self.classlist.column("#0", width=40, minwidth=35, stretch=tk.YES)
        self.classlist.column("#1", width=150, minwidth=150, stretch=tk.YES)
        self.classlist.column("#2", width=270, minwidth=270, stretch=tk.YES)

        # gui style
        self.lbl_file.pack(anchor="w")
        self.classlist.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
        self.yscrollbar.config(command=self.classlist.yview)
        self.xscrollbar.config(command=self.classlist.xview)

    def loadFile(self):
        self.classlist.delete(*self.classlist.get_children())
        self.file_path = filedialog.askopenfilename(
            filetypes=(("Executable files", "*.exe"),
                       ("DLL Library", "*.dll"), ("all files", "*.*")))
        if self.file_path == '':
            print("Error - Invalid target path!")
            return
        self.lbl_file['text'] = ntpath.basename(self.file_path)
        self.update_idletasks()
        self.scanner = rtti.RTTIScanner(self.file_path)
        self.scanner.scan()
        for i in range(len(self.scanner.vftables)):
            self.classlist.insert("", i,
                                  text=str(i),
                                  values=(hex(self.scanner.vftables[i]),self.scanner.symbols[i].replace(" ", "\ ")))

    def exportData(self):
        save_file_path = filedialog.asksaveasfilename()
        if save_file_path == None:
            print("Error - Invalid export path")
            return
        try:
            with open(save_file_path, 'w') as file:
                data = self.classlist.to_str()
                file.write(data)
                file.close()
        finally:
            return




def main():
    app = PyClassInformer(tk.Tk())
    app.mainloop()


if __name__ == '__main__':
    main()
