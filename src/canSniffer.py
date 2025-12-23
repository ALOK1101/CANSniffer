import serial
import threading
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import time

# --- USTAWIENIA PROJEKTU ---
PORT = 'COM7'
BAUD = 115200  # Zgodnie z natywną prędkością ESP32
DB_IDS = 'deciphered_ids.json'
DB_FUNCTIONS = 'function_codes.json'

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ModernCANApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CAN Analyzer Pro v3.3 - 115200 bps")
        self.geometry("1650x800")

        self.can_rows = {}
        self.id_labels = self._load_db(DB_IDS)
        self.function_labels = self._load_db(DB_FUNCTIONS)
        self.row_counter = 1

        self._build_ui()
        # Uruchomienie wątku nasłuchującego
        threading.Thread(target=self._serial_listener, daemon=True).start()

    def _load_db(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_db(self, path, data):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=220)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(self.sidebar, text="BAZY DANYCH", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(self.sidebar, text="Zarządzaj ID", command=self.win_manage_ids).pack(pady=5, padx=10)
        ctk.CTkButton(self.sidebar, text="Zarządzaj Funkcjami", command=self.win_manage_funcs).pack(pady=5, padx=10)

        ctk.CTkButton(self.sidebar, text="Wyczyść Monitor", fg_color="#C0392B", command=self._clear_monitor).pack(
            pady=(30, 5), padx=10)
        self.status_lbl = ctk.CTkLabel(self.sidebar, text="STATUS: 115200", text_color="green")
        self.status_lbl.pack(pady=20)

        self.scroll = ctk.CTkScrollableFrame(self, label_text="Live Monitor (D0-D7)")
        self.scroll.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        # Zaktualizowane nagłówki o RTR i IDE
        headers = ["ID", "Urządzenie", "Funkcja", "RTR", "IDE", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "Zapis"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(self.scroll, text=h, font=ctk.CTkFont(weight="bold"), width=50).grid(row=0, column=i, padx=5,
                                                                                              pady=5)

    def update_monitor(self, can_id, rtr, ide, dlc, bytes_list):
        data_str = " ".join(bytes_list)

        if can_id not in self.can_rows:
            # --- NOWE ID: PODŚWIETLENIE NIEBIESKIE (2s) ---
            row = self.row_counter
            self.row_counter += 1
            hi_bg = "#1B4F72"

            id_l = ctk.CTkLabel(self.scroll, text=can_id, text_color="#3498DB", cursor="hand2", fg_color=hi_bg)
            id_l.grid(row=row, column=0, padx=2, pady=1)
            id_l.bind("<Button-1>", lambda e, cid=can_id: self._open_id_edit(cid))

            dev_name = self.id_labels.get(can_id, "---")
            dev_l = ctk.CTkLabel(self.scroll, text=dev_name, fg_color=hi_bg,
                                 text_color="gray" if dev_name == "---" else "#2ECC71")
            dev_l.grid(row=row, column=1, padx=2, pady=1)

            mapping = self.function_labels.get(can_id, {})
            det_func = mapping.get("mappings", {}).get(data_str, "---")
            func_l = ctk.CTkLabel(self.scroll, text=det_func, fg_color=hi_bg,
                                  text_color="#F1C40F" if det_func != "---" else "gray")
            func_l.grid(row=row, column=2, padx=2, pady=1)

            # Nowe kolumny RTR i IDE
            rtr_l = ctk.CTkLabel(self.scroll, text=rtr, fg_color=hi_bg)
            rtr_l.grid(row=row, column=3, padx=2, pady=1)

            ide_l = ctk.CTkLabel(self.scroll, text=ide, fg_color=hi_bg)
            ide_l.grid(row=row, column=4, padx=2, pady=1)

            dlc_l = ctk.CTkLabel(self.scroll, text=dlc, fg_color=hi_bg)
            dlc_l.grid(row=row, column=5, padx=2, pady=1)

            b_labels = []
            for j in range(8):
                val = bytes_list[j] if j < len(bytes_list) else "00"
                l = ctk.CTkLabel(self.scroll, text=val, width=40, fg_color=hi_bg)
                l.grid(row=row, column=6 + j, padx=2, pady=1)
                b_labels.append(l)

            btn = ctk.CTkButton(self.scroll, text="+", width=40, command=lambda cid=can_id: self._save_function(cid))
            btn.grid(row=row, column=14, padx=5)

            # Lista widgetów do wygaszania/usuwania (dodano rtr_l i ide_l)
            widgets = [id_l, dev_l, func_l, rtr_l, ide_l, dlc_l] + b_labels
            self.can_rows[can_id] = {'dev_lbl': dev_l, 'func_lbl': func_l, 'bytes': b_labels, 'last_data': bytes_list,
                                     'widgets': widgets + [btn]}

            def fade():
                try:
                    for w in widgets:
                        if w.winfo_exists(): w.configure(fg_color="transparent")
                except:
                    pass

            self.after(2000, fade)
        else:
            # --- AKTUALIZACJA: PODŚWIETLENIE DELTA (0.35s) ---
            r = self.can_rows[can_id]
            mapping = self.function_labels.get(can_id, {})
            det_func = mapping.get("mappings", {}).get(data_str, "---")
            r['func_lbl'].configure(text=det_func, text_color="#F1C40F" if det_func != "---" else "gray")

            for i in range(len(bytes_list)):
                if i < len(r['last_data']) and bytes_list[i] != r['last_data'][i]:
                    lbl = r['bytes'][i]
                    lbl.configure(text=bytes_list[i], text_color="#FF5555", font=ctk.CTkFont(weight="bold"),
                                  fg_color="#4A1515")

                    def reset(l=lbl):
                        try:
                            if l.winfo_exists(): l.configure(text_color="white", font=ctk.CTkFont(weight="normal"),
                                                             fg_color="transparent")
                        except:
                            pass

                    self.after(350, reset)
                    r['last_data'][i] = bytes_list[i]

    def _save_function(self, can_id):
        data_str = " ".join(self.can_rows[can_id]['last_data'])
        dev_label = self.id_labels.get(can_id, "Nieznane")
        d = ctk.CTkInputDialog(text=f"ID: {can_id}\nEtykieta: {dev_label}\nFunkcja dla: {data_str}",
                               title="Baza Funkcji")
        val = d.get_input()
        if val:
            if can_id not in self.function_labels: self.function_labels[can_id] = {"device": dev_label, "mappings": {}}
            self.function_labels[can_id]["device"] = dev_label
            self.function_labels[can_id]["mappings"][data_str] = val
            self._save_db(DB_FUNCTIONS, self.function_labels)
            self.can_rows[can_id]['func_lbl'].configure(text=val, text_color="#F1C40F")

    def win_manage_ids(self):
        win = ctk.CTkToplevel(self)
        win.title("Edycja Bazy ID")
        win.geometry("500x500")
        win.attributes("-topmost", True)
        tree = ttk.Treeview(win, columns=("id", "name"), show='headings')
        tree.heading("id", text="ID")
        tree.heading("name", text="Urządzenie")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def reload():
            for i in tree.get_children(): tree.delete(i)
            for k, v in self.id_labels.items(): tree.insert('', tk.END, values=(k, v))

        def delete():
            sel = tree.selection()
            if sel:
                cid = str(tree.item(sel[0])['values'][0])
                if messagebox.askyesno("Usuń", f"Usunąć {cid}?"):
                    del self.id_labels[cid]
                    self._save_db(DB_IDS, self.id_labels)
                    reload()

        f = ctk.CTkFrame(win)
        f.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(f, text="Usuń", fg_color="#C0392B", command=delete).pack(side="left", padx=5)
        reload()

    def win_manage_funcs(self):
        win = ctk.CTkToplevel(self)
        win.title("Edycja Funkcji")
        win.geometry("800x500")
        win.attributes("-topmost", True)
        tree = ttk.Treeview(win, columns=("id", "dev", "data", "func"), show='headings')
        tree.heading("id", text="ID")
        tree.heading("dev", text="Urządzenie")
        tree.heading("data", text="Wzorzec")
        tree.heading("func", text="Funkcja")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def reload():
            for i in tree.get_children(): tree.delete(i)
            for cid, obj in self.function_labels.items():
                for d, f in obj.get("mappings", {}).items(): tree.insert('', tk.END,
                                                                         values=(cid, obj.get("device", "---"), d, f))

        def delete():
            sel = tree.selection()
            if sel:
                v = tree.item(sel[0])['values']
                cid, d_str = str(v[0]), str(v[2])
                if messagebox.askyesno("Usuń", "Usunąć funkcję?"):
                    del self.function_labels[cid]["mappings"][d_str]
                    if not self.function_labels[cid]["mappings"]: del self.function_labels[cid]
                    self._save_db(DB_FUNCTIONS, self.function_labels)
                    reload()

        f = ctk.CTkFrame(win)
        f.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(f, text="Usuń", fg_color="#C0392B", command=delete).pack(side="left", padx=5)
        reload()

    def _serial_listener(self):
        try:
            ser = serial.Serial(PORT, BAUD, timeout=1)
            while True:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if line.startswith("FRAME:"):
                    p = line.replace("FRAME:", "").split("|")
                    # Poprawione przekazywanie: ID (p[0]), RTR (p[1]), IDE (p[2]), DLC (p[3]), DATA (p[4])
                    if len(p) >= 5:
                        self.after(0, self.update_monitor, p[0], p[1], p[2], p[3], p[4].split(" "))
        except:
            self.after(0, lambda: self.status_lbl.configure(text="BŁĄD PORTU", text_color="red"))

    def _open_id_edit(self, can_id):
        d = ctk.CTkInputDialog(text=f"Etykieta dla {can_id}:", title="Baza ID")
        v = d.get_input()
        if v:
            self.id_labels[can_id] = v
            self._save_db(DB_IDS, self.id_labels)
            if can_id in self.can_rows: self.can_rows[can_id]['dev_lbl'].configure(text=v, text_color="#2ECC71")

    def _clear_monitor(self):
        for r in self.can_rows.values():
            for w in r['widgets']: w.destroy()
        self.can_rows.clear()
        self.row_counter = 1


if __name__ == "__main__":
    app = ModernCANApp()
    app.mainloop()