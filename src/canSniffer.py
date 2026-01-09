import serial
import serial.tools.list_ports
import threading
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import time
from datetime import datetime

# --- USTAWIENIA PROJEKTU ---
BAUD = 115200
DB_IDS = 'deciphered_ids.json'
DB_FUNCTIONS = 'function_codes.json'
MAX_ALL_ROWS = 100  # Bufor dla widoku strumieniowego

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ModernCANApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CAN Analyzer Pro v4.1 - Ultimate Hybrid")
        self.geometry("1650x800")

        # Struktury danych
        self.can_rows = {}  # Dla widoku Grouped
        self.all_msgs_widgets = []  # Dla widoku All Messages

        # Ładowanie baz danych
        self.id_labels = self._load_db(DB_IDS)
        self.function_labels = self._load_db(DB_FUNCTIONS)

        self.row_counter_grouped = 1
        self.row_counter_all = 1

        # Stan połączenia
        self.ser = None
        self.is_sniffing = False
        self.is_sending_active = False
        self.is_paused = False

        self._build_ui()
        self._update_tx_list()

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

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=250)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 1. TRYB WIDOKU
        ctk.CTkLabel(self.sidebar, text="TRYB WIDOKU", font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))
        self.view_mode = ctk.StringVar(value="Grouped Messages")
        self.seg_view = ctk.CTkSegmentedButton(self.sidebar, values=["Grouped Messages", "All Messages"],
                                               command=self.toggle_view_mode, variable=self.view_mode)
        self.seg_view.pack(pady=5, padx=10)

        # 2. KONFIGURACJA
        ctk.CTkLabel(self.sidebar, text="KONFIGURACJA", font=ctk.CTkFont(weight="bold")).pack(pady=(15, 5))
        self.port_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.port_frame.pack(pady=5, padx=10, fill="x")

        self.port_combo = ctk.CTkComboBox(self.port_frame, width=150)
        self.port_combo.pack(side="left", padx=(0, 5))
        self.btn_refresh = ctk.CTkButton(self.port_frame, text="⟳", width=30, command=self.refresh_ports,
                                         fg_color="#F39C12")
        self.btn_refresh.pack(side="left")
        self.refresh_ports()

        self.btn_connect = ctk.CTkButton(self.sidebar, text="POŁĄCZ", fg_color="green", command=self.toggle_connection)
        self.btn_connect.pack(pady=(10, 5), padx=10)

        # Przycisk PAUZA
        self.btn_pause = ctk.CTkButton(self.sidebar, text="PAUZA (ZAMROŹ)", fg_color="#E67E22", state="disabled",
                                       command=self.toggle_pause)
        self.btn_pause.pack(pady=5, padx=10)

        # 3. NADAWANIE (TX)
        ctk.CTkLabel(self.sidebar, text="NADAWANIE (TX)", font=ctk.CTkFont(weight="bold")).pack(pady=(20, 5))
        self.tx_combo = ctk.CTkComboBox(self.sidebar, values=["Brak funkcji"], width=220)
        self.tx_combo.pack(pady=5, padx=10)

        self.tx_settings_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.tx_settings_frame.pack(pady=5, padx=10, fill="x")
        ctk.CTkLabel(self.tx_settings_frame, text="Ilość:", font=("Arial", 11)).grid(row=0, column=0, padx=2,
                                                                                     sticky="w")
        self.entry_repeat = ctk.CTkEntry(self.tx_settings_frame, width=60)
        self.entry_repeat.grid(row=0, column=1, padx=2)
        self.entry_repeat.insert(0, "1")
        ctk.CTkLabel(self.tx_settings_frame, text="Odstęp (ms):", font=("Arial", 11)).grid(row=1, column=0, padx=2,
                                                                                           sticky="w", pady=(5, 0))
        self.entry_interval = ctk.CTkEntry(self.tx_settings_frame, width=60)
        self.entry_interval.grid(row=1, column=1, padx=2, pady=(5, 0))
        self.entry_interval.insert(0, "100")
        self.btn_send = ctk.CTkButton(self.sidebar, text="WYŚLIJ ROZKAZ", fg_color="#D35400",
                                      command=self.handle_send_click)
        self.btn_send.pack(pady=15, padx=10)

        # 4. ZARZĄDZANIE BAZĄ (Restore functionality)
        ctk.CTkLabel(self.sidebar, text="BAZY DANYCH", font=ctk.CTkFont(weight="bold")).pack(pady=(20, 5))
        ctk.CTkButton(self.sidebar, text="Zarządzaj ID", command=self.win_manage_ids).pack(pady=5, padx=10)
        ctk.CTkButton(self.sidebar, text="Zarządzaj Funkcjami", command=self.win_manage_funcs).pack(pady=5, padx=10)

        ctk.CTkButton(self.sidebar, text="Wyczyść Monitor", fg_color="#C0392B", command=self._clear_monitor).pack(
            pady=(30, 5), padx=10)
        self.status_lbl = ctk.CTkLabel(self.sidebar, text="STATUS: ROZŁĄCZONY", text_color="gray")
        self.status_lbl.pack(pady=20)

        # --- WIDOK 1: GROUPED ---
        self.scroll_grouped = ctk.CTkScrollableFrame(self, label_text="Grouped Messages (Unique ID)")
        self.scroll_grouped.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        headers_grouped = ["ID", "Urządzenie", "Funkcja", "RTR", "IDE", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6",
                           "D7", "Zapis"]
        for i, h in enumerate(headers_grouped):
            ctk.CTkLabel(self.scroll_grouped, text=h, font=ctk.CTkFont(weight="bold"), width=50).grid(row=0, column=i,
                                                                                                      padx=5, pady=5)

        # --- WIDOK 2: ALL MESSAGES ---
        self.scroll_all = ctk.CTkScrollableFrame(self, label_text="All Messages Stream (Buffer: 100)")
        headers_all = ["ID", "Urządzenie", "Funkcja", "RTR", "IDE", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6",
                       "D7", "Czas"]
        for i, h in enumerate(headers_all):
            ctk.CTkLabel(self.scroll_all, text=h, font=ctk.CTkFont(weight="bold"), width=50).grid(row=0, column=i,
                                                                                                  padx=5, pady=5)

    # --- LOGIKA UI ---
    def toggle_view_mode(self, value):
        if value == "Grouped Messages":
            self.scroll_all.grid_forget()
            self.scroll_grouped.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        else:
            self.scroll_grouped.grid_forget()
            self.scroll_all.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        if not ports:
            ports = ["Brak"]
            self.port_combo.set("Brak")
        else:
            self.port_combo.set(ports[0])
        self.port_combo.configure(values=ports)

    def _update_tx_list(self):
        items = []
        for cid, obj in self.function_labels.items():
            dev_name = obj.get("device", "Unknown")
            for data_pattern, func_name in obj.get("mappings", {}).items():
                items.append(f"[{cid}] {func_name} ({dev_name})")
        if not items: items = ["Brak zapisanych funkcji"]
        items.sort()
        self.tx_combo.configure(values=items)
        if items: self.tx_combo.set(items[0])

    # --- LOGIKA POŁĄCZENIA ---
    def toggle_connection(self):
        if not self.is_sniffing:
            selected_port = self.port_combo.get()
            if selected_port == "Brak" or not selected_port:
                messagebox.showerror("Błąd", "Nie wykryto portów COM!")
                return
            try:
                self.ser = serial.Serial(selected_port, BAUD, timeout=0.1)
                self.is_sniffing = True
                self.is_paused = False

                self.btn_connect.configure(text="ROZŁĄCZ", fg_color="#C0392B")
                self.status_lbl.configure(text="STATUS: POŁĄCZONY", text_color="green")
                self.port_combo.configure(state="disabled")
                self.btn_refresh.configure(state="disabled")
                self.btn_pause.configure(state="normal", text="PAUZA (ZAMROŹ)", fg_color="#E67E22")

                threading.Thread(target=self._serial_listener, daemon=True).start()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
        else:
            self._disconnect_cleanup()

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.btn_pause.configure(text="WZNÓW PODGLĄD", fg_color="#27AE60")
            self.status_lbl.configure(text="STATUS: ZAMROŻONY", text_color="orange")
        else:
            self.btn_pause.configure(text="PAUZA (ZAMROŹ)", fg_color="#E67E22")
            self.status_lbl.configure(text="STATUS: POŁĄCZONY", text_color="green")

    def _disconnect_cleanup(self):
        self.is_sniffing = False
        self.is_sending_active = False
        self.is_paused = False
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None
        self.after(0, lambda: self.btn_connect.configure(text="POŁĄCZ", fg_color="green"))
        self.after(0, lambda: self.status_lbl.configure(text="STATUS: ZATRZYMANO", text_color="orange"))
        self.after(0, lambda: self.port_combo.configure(state="normal"))
        self.after(0, lambda: self.btn_refresh.configure(state="normal"))
        self.after(0, lambda: self.btn_send.configure(text="WYŚLIJ ROZKAZ", fg_color="#D35400"))
        self.after(0, lambda: self.btn_pause.configure(state="disabled", text="PAUZA (ZAMROŹ)", fg_color="#E67E22"))

    def _serial_listener(self):
        while self.is_sniffing:
            try:
                if self.ser and self.ser.is_open:
                    if self.ser.in_waiting:
                        try:
                            line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                            if line.startswith("FRAME:"):
                                p = line.replace("FRAME:", "").split("|")
                                if len(p) >= 5:
                                    if not self.is_paused:
                                        self.after(0, self.update_monitor, p[0], p[1], p[2], p[3], p[4].split(" "))
                        except Exception:
                            pass
                    else:
                        time.sleep(0.005)
                else:
                    break
            except Exception:
                self.is_sniffing = False
                self.after(0, self._disconnect_cleanup)
                break

    # --- LOGIKA NADAWANIA (TX) ---
    def handle_send_click(self):
        if self.is_sending_active:
            self.is_sending_active = False
            self.btn_send.configure(text="WYŚLIJ ROZKAZ", fg_color="#D35400")
            return
        if not self.ser or not self.ser.is_open:
            messagebox.showwarning("Błąd", "Brak połączenia!")
            return
        selection = self.tx_combo.get()
        if not selection or selection == "Brak zapisanych funkcji": return

        try:
            count = int(self.entry_repeat.get())
            interval_ms = int(self.entry_interval.get())
        except:
            return

        target_id = selection.split("]")[0].replace("[", "")
        data_to_send = None
        if target_id in self.function_labels:
            mappings = self.function_labels[target_id].get("mappings", {})
            for d_str, f_name in mappings.items():
                if f"[{target_id}] {f_name} ({self.function_labels[target_id].get('device', '?')})" == selection:
                    data_to_send = d_str
                    break

        if data_to_send:
            self.is_sending_active = True
            self.btn_send.configure(text="ZATRZYMAJ", fg_color="#C0392B")
            threading.Thread(target=self._sending_loop, args=(target_id, data_to_send, count, interval_ms),
                             daemon=True).start()

    def _sending_loop(self, target_id, data_str, count, interval_ms):
        command = f"SEND:{target_id}|{data_str}\n"
        encoded = command.encode('utf-8')
        for i in range(count):
            if not self.is_sending_active or not self.is_sniffing: break
            try:
                self.ser.write(encoded)
            except:
                self.is_sending_active = False
                break
            time.sleep(interval_ms / 1000.0)
        self.is_sending_active = False
        self.after(0, lambda: self.btn_send.configure(text="WYŚLIJ ROZKAZ", fg_color="#D35400"))

    # --- ZARZĄDZANIE BAZAMI DANYCH (Przywrócone z Twojego kodu) ---
    def win_manage_ids(self):
        win = ctk.CTkToplevel(self)
        win.title("Zarządzanie ID")
        win.geometry("500x500")
        win.attributes("-topmost", True)
        tree = ttk.Treeview(win, columns=("id", "name"), show='headings')
        tree.heading("id", text="ID (Hex)");
        tree.heading("name", text="Nazwa Urządzenia")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def reload():
            for i in tree.get_children(): tree.delete(i)
            for k in sorted(self.id_labels.keys()): tree.insert('', tk.END, values=(k, self.id_labels[k]))

        def delete():
            sel = tree.selection()
            if sel:
                cid = str(tree.item(sel[0])['values'][0])
                if messagebox.askyesno("Usuń", f"Czy na pewno usunąć opis dla ID {cid}?"):
                    del self.id_labels[cid]
                    self._save_db(DB_IDS, self.id_labels)
                    if cid in self.can_rows: self.can_rows[cid]['dev_lbl'].configure(text="---", text_color="gray")
                    reload();
                    self._update_tx_list()

        def edit():
            sel = tree.selection()
            if sel:
                cid = str(tree.item(sel[0])['values'][0])
                old_name = self.id_labels.get(cid, "")
                dialog = ctk.CTkInputDialog(text=f"Edytuj nazwę dla ID {cid}:\n(Aktualnie: {old_name})",
                                            title="Edycja ID")
                new_name = dialog.get_input()
                if new_name:
                    self.id_labels[cid] = new_name
                    self._save_db(DB_IDS, self.id_labels)
                    if cid in self.can_rows: self.can_rows[cid]['dev_lbl'].configure(text=new_name,
                                                                                     text_color="#2ECC71")
                    reload();
                    self._update_tx_list()
            else:
                messagebox.showinfo("Info", "Zaznacz wiersz do edycji.")

        f = ctk.CTkFrame(win);
        f.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(f, text="Usuń", fg_color="#C0392B", width=100, command=delete).pack(side="left", padx=5)
        ctk.CTkButton(f, text="Edytuj", fg_color="#F39C12", width=100, command=edit).pack(side="left", padx=5)
        reload()

    def win_manage_funcs(self):
        win = ctk.CTkToplevel(self)
        win.title("Zarządzanie Funkcjami")
        win.geometry("900x500")
        win.attributes("-topmost", True)
        tree = ttk.Treeview(win, columns=("id", "dev", "data", "func"), show='headings')
        tree.heading("id", text="ID");
        tree.heading("dev", text="Urządzenie");
        tree.heading("data", text="Wzorzec Danych");
        tree.heading("func", text="Opis Funkcji")
        tree.column("id", width=60, anchor="center");
        tree.column("dev", width=150, anchor="w");
        tree.column("data", width=250, anchor="center");
        tree.column("func", width=300, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def reload():
            for i in tree.get_children(): tree.delete(i)
            for cid in sorted(self.function_labels.keys()):
                obj = self.function_labels[cid]
                for d, f in obj.get("mappings", {}).items(): tree.insert('', tk.END,
                                                                         values=(cid, obj.get("device", "---"), d, f))

        def delete():
            sel = tree.selection()
            if sel:
                v = tree.item(sel[0])['values']
                cid, d_str = str(v[0]), str(v[2])
                if messagebox.askyesno("Usuń", "Usunąć tę funkcję?"):
                    del self.function_labels[cid]["mappings"][d_str]
                    if not self.function_labels[cid]["mappings"]: del self.function_labels[cid]
                    self._save_db(DB_FUNCTIONS, self.function_labels)
                    reload();
                    self._update_tx_list()

        def edit():
            sel = tree.selection()
            if sel:
                v = tree.item(sel[0])['values']
                cid = str(v[0]);
                d_str = str(v[2]);
                old_func = str(v[3])
                dialog = ctk.CTkInputDialog(text=f"Edytuj opis funkcji dla ID {cid}:\n[{d_str}]",
                                            title="Edycja Funkcji")
                new_func = dialog.get_input()
                if new_func:
                    self.function_labels[cid]["mappings"][d_str] = new_func
                    self._save_db(DB_FUNCTIONS, self.function_labels)
                    if cid in self.can_rows:
                        current_data = " ".join(self.can_rows[cid]['last_data'])
                        if current_data == d_str: self.can_rows[cid]['func_lbl'].configure(text=new_func,
                                                                                           text_color="#F1C40F")
                    reload();
                    self._update_tx_list()
            else:
                messagebox.showinfo("Info", "Zaznacz wiersz do edycji.")

        f = ctk.CTkFrame(win);
        f.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(f, text="Usuń", fg_color="#C0392B", width=100, command=delete).pack(side="left", padx=5)
        ctk.CTkButton(f, text="Edytuj", fg_color="#F39C12", width=100, command=edit).pack(side="left", padx=5)
        reload()

    def _open_id_edit(self, can_id):
        d = ctk.CTkInputDialog(text=f"Etykieta dla {can_id}:", title="Baza ID")
        v = d.get_input()
        if v:
            self.id_labels[can_id] = v
            self._save_db(DB_IDS, self.id_labels)
            if can_id in self.can_rows: self.can_rows[can_id]['dev_lbl'].configure(text=v, text_color="#2ECC71")
            self._update_tx_list()

    def _save_function(self, can_id):
        if can_id in self.can_rows:
            data_str = " ".join(self.can_rows[can_id]['last_data'])
        else:
            return
        dev_label = self.id_labels.get(can_id, "Nieznane")
        d = ctk.CTkInputDialog(text=f"ID: {can_id}\nEtykieta: {dev_label}\nFunkcja dla: {data_str}",
                               title="Baza Funkcji")
        val = d.get_input()
        if val:
            if can_id not in self.function_labels: self.function_labels[can_id] = {"device": dev_label, "mappings": {}}
            self.function_labels[can_id]["device"] = dev_label
            self.function_labels[can_id]["mappings"][data_str] = val
            self._save_db(DB_FUNCTIONS, self.function_labels)
            if can_id in self.can_rows:
                self.can_rows[can_id]['func_lbl'].configure(text=val, text_color="#F1C40F")
            self._update_tx_list()

    def _clear_monitor(self):
        for r in self.can_rows.values():
            for w in r['widgets']: w.destroy()
        self.can_rows.clear()
        self.row_counter_grouped = 1

        for row_widgets in self.all_msgs_widgets:
            for w in row_widgets: w.destroy()
        self.all_msgs_widgets.clear()
        self.row_counter_all = 1

    # --- GLÓWNA LOGIKA AKTUALIZACJI ---
    def update_monitor(self, can_id, rtr, ide, dlc, bytes_list):
        data_str = " ".join(bytes_list)
        current_mode = self.view_mode.get()

        dev_name = self.id_labels.get(can_id, "---")
        mapping = self.function_labels.get(can_id, {})
        det_func = mapping.get("mappings", {}).get(data_str, "---")

        if current_mode == "All Messages":
            if len(self.all_msgs_widgets) >= MAX_ALL_ROWS:
                oldest_row_widgets = self.all_msgs_widgets.pop(0)
                for w in oldest_row_widgets: w.destroy()

            row = self.row_counter_all
            self.row_counter_all += 1
            bg_color = "#2C3E50" if row % 2 == 0 else "#212F3D"

            widgets_in_this_row = []

            def add_lbl(txt, col, color="white"):
                l = ctk.CTkLabel(self.scroll_all, text=txt, fg_color=bg_color, text_color=color)
                l.grid(row=row, column=col, padx=2, pady=1, sticky="nsew")
                widgets_in_this_row.append(l)

            add_lbl(can_id, 0, "#3498DB")
            add_lbl(dev_name, 1, "gray" if dev_name == "---" else "#2ECC71")
            add_lbl(det_func, 2, "#F1C40F" if det_func != "---" else "gray")
            add_lbl(rtr, 3)
            add_lbl(ide, 4)
            add_lbl(dlc, 5)

            for j in range(8):
                val = bytes_list[j] if j < len(bytes_list) else "00"
                byte_color = "white" if val == "00" else "#E74C3C"
                add_lbl(val, 6 + j, byte_color)

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            add_lbl(timestamp, 14, "gray")
            self.all_msgs_widgets.append(widgets_in_this_row)

        else:
            if can_id not in self.can_rows:
                row = self.row_counter_grouped
                self.row_counter_grouped += 1
                hi_bg = "#1B4F72"

                id_l = ctk.CTkLabel(self.scroll_grouped, text=can_id, text_color="#3498DB", cursor="hand2",
                                    fg_color=hi_bg)
                id_l.grid(row=row, column=0, padx=2, pady=1)
                id_l.bind("<Button-1>", lambda e, cid=can_id: self._open_id_edit(cid))

                dev_l = ctk.CTkLabel(self.scroll_grouped, text=dev_name, fg_color=hi_bg,
                                     text_color="gray" if dev_name == "---" else "#2ECC71")
                dev_l.grid(row=row, column=1, padx=2, pady=1)

                func_l = ctk.CTkLabel(self.scroll_grouped, text=det_func, fg_color=hi_bg,
                                      text_color="#F1C40F" if det_func != "---" else "gray")
                func_l.grid(row=row, column=2, padx=2, pady=1)

                rtr_l = ctk.CTkLabel(self.scroll_grouped, text=rtr, fg_color=hi_bg)
                rtr_l.grid(row=row, column=3, padx=2, pady=1)
                ide_l = ctk.CTkLabel(self.scroll_grouped, text=ide, fg_color=hi_bg)
                ide_l.grid(row=row, column=4, padx=2, pady=1)
                dlc_l = ctk.CTkLabel(self.scroll_grouped, text=dlc, fg_color=hi_bg)
                dlc_l.grid(row=row, column=5, padx=2, pady=1)

                b_labels = []
                for j in range(8):
                    val = bytes_list[j] if j < len(bytes_list) else "00"
                    l = ctk.CTkLabel(self.scroll_grouped, text=val, width=40, fg_color=hi_bg)
                    l.grid(row=row, column=6 + j, padx=2, pady=1)
                    b_labels.append(l)

                btn = ctk.CTkButton(self.scroll_grouped, text="+", width=40,
                                    command=lambda cid=can_id: self._save_function(cid))
                btn.grid(row=row, column=14, padx=5)

                widgets = [id_l, dev_l, func_l, rtr_l, ide_l, dlc_l] + b_labels
                self.can_rows[can_id] = {'dev_lbl': dev_l, 'func_lbl': func_l, 'bytes': b_labels,
                                         'last_data': bytes_list, 'widgets': widgets + [btn]}

                def fade():
                    try:
                        for w in widgets:
                            if w.winfo_exists(): w.configure(fg_color="transparent")
                    except:
                        pass

                self.after(2000, fade)

            else:
                r = self.can_rows[can_id]
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


if __name__ == "__main__":
    app = ModernCANApp()
    app.mainloop()