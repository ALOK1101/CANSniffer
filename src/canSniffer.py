import serial
import serial.tools.list_ports
import threading
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import time

# --- USTAWIENIA PROJEKTU ---
BAUD = 115200
DB_IDS = 'deciphered_ids.json'
DB_FUNCTIONS = 'function_codes.json'

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ModernCANApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CAN Analyzer Pro v3.6 - Stable & Robust")
        self.geometry("1650x800")

        self.can_rows = {}
        self.id_labels = self._load_db(DB_IDS)
        self.function_labels = self._load_db(DB_FUNCTIONS)
        self.row_counter = 1

        self.ser = None
        self.is_sniffing = False
        self.is_sending_active = False

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

        # 1. KONFIGURACJA
        ctk.CTkLabel(self.sidebar, text="KONFIGURACJA", font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))

        # Ramka na ComboBox i przycisk odświeżania
        self.port_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.port_frame.pack(pady=5, padx=10, fill="x")

        self.port_combo = ctk.CTkComboBox(self.port_frame, width=150)
        self.port_combo.pack(side="left", padx=(0, 5))

        # Przycisk Odśwież (mały, z symbolem)
        self.btn_refresh = ctk.CTkButton(self.port_frame, text="⟳", width=30, command=self.refresh_ports,
                                         fg_color="#F39C12")
        self.btn_refresh.pack(side="left")

        # Inicjalne załadowanie portów
        self.refresh_ports()

        self.btn_connect = ctk.CTkButton(self.sidebar, text="POŁĄCZ", fg_color="green", command=self.toggle_connection)
        self.btn_connect.pack(pady=10, padx=10)

        # 2. NADAWANIE (TX)
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

        # 3. BAZY DANYCH
        ctk.CTkLabel(self.sidebar, text="BAZY DANYCH", font=ctk.CTkFont(weight="bold")).pack(pady=(20, 5))
        ctk.CTkButton(self.sidebar, text="Zarządzaj ID", command=self.win_manage_ids).pack(pady=5, padx=10)
        ctk.CTkButton(self.sidebar, text="Zarządzaj Funkcjami", command=self.win_manage_funcs).pack(pady=5, padx=10)

        ctk.CTkButton(self.sidebar, text="Wyczyść Monitor", fg_color="#C0392B", command=self._clear_monitor).pack(
            pady=(30, 5), padx=10)

        self.status_lbl = ctk.CTkLabel(self.sidebar, text="STATUS: ROZŁĄCZONY", text_color="gray")
        self.status_lbl.pack(pady=20)

        # --- SCROLL FRAME ---
        self.scroll = ctk.CTkScrollableFrame(self, label_text="Live Monitor (B-CAN Traffic)")
        self.scroll.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        headers = ["ID", "Urządzenie", "Funkcja", "RTR", "IDE", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
                   "Zapis"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(self.scroll, text=h, font=ctk.CTkFont(weight="bold"), width=50).grid(row=0, column=i, padx=5,
                                                                                              pady=5)

    def refresh_ports(self):
        """Skanuje dostępne porty COM i aktualizuje listę"""
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
                display_str = f"[{cid}] {func_name} ({dev_name})"
                items.append(display_str)

        if not items: items = ["Brak zapisanych funkcji"]
        items.sort()
        self.tx_combo.configure(values=items)
        if items: self.tx_combo.set(items[0])

    def toggle_connection(self):
        if not self.is_sniffing:
            # --- PRÓBA POŁĄCZENIA ---
            selected_port = self.port_combo.get()
            if selected_port == "Brak" or not selected_port:
                messagebox.showerror("Błąd", "Nie wykryto portów COM!\nPodłącz urządzenie i kliknij ⟳.")
                return

            try:
                # Otwieramy port
                self.ser = serial.Serial(selected_port, BAUD, timeout=0.1)
                self.is_sniffing = True

                # Zmiana UI
                self.btn_connect.configure(text="ROZŁĄCZ", fg_color="#C0392B")
                self.status_lbl.configure(text="STATUS: POŁĄCZONY", text_color="green")
                self.port_combo.configure(state="disabled")  # Blokada zmiany portu
                self.btn_refresh.configure(state="disabled")

                # Start wątku
                threading.Thread(target=self._serial_listener, daemon=True).start()

            except serial.SerialException as e:
                # Obsługa zajętego portu lub braku dostępu
                if "Access is denied" in str(e):
                    messagebox.showerror("Błąd Portu",
                                         f"Port {selected_port} jest zajęty!\nZamknij inne programy (np. Arduino IDE).")
                else:
                    messagebox.showerror("Błąd Portu", f"Nie można otworzyć portu:\n{str(e)}")
            except Exception as e:
                messagebox.showerror("Błąd Krytyczny", str(e))
        else:
            # --- ROZŁĄCZANIE RĘCZNE ---
            self._disconnect_cleanup()

    def _disconnect_cleanup(self):
        """Bezpieczne zamykanie połączenia i reset UI"""
        self.is_sniffing = False
        self.is_sending_active = False

        # Zamykanie portu
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None

        # Reset UI (używamy after, bo może być wywołane z wątku tła)
        self.after(0, lambda: self.btn_connect.configure(text="POŁĄCZ", fg_color="green"))
        self.after(0, lambda: self.status_lbl.configure(text="STATUS: ZATRZYMANO", text_color="orange"))
        self.after(0, lambda: self.port_combo.configure(state="normal"))
        self.after(0, lambda: self.btn_refresh.configure(state="normal"))
        self.after(0, lambda: self.btn_send.configure(text="WYŚLIJ ROZKAZ", fg_color="#D35400"))

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
                                    self.after(0, self.update_monitor, p[0], p[1], p[2], p[3], p[4].split(" "))
                        except UnicodeDecodeError:
                            pass
                        except OSError:
                            # Błąd odczytu (np. nagłe wyrwanie kabla)
                            raise serial.SerialException("Device disconnected")
                    else:
                        time.sleep(0.005)
                else:
                    break
            except (serial.SerialException, OSError):
                # --- DETEKCJA NAGŁEGO ROZŁĄCZENIA ---
                self.is_sniffing = False
                self.after(0, lambda: self.status_lbl.configure(text="BŁĄD: UTRACONO POŁĄCZENIE", text_color="red"))
                self.after(0, self._disconnect_cleanup)
                break
            except Exception as e:
                print(f"Unknown Error: {e}")
                break

    def handle_send_click(self):
        if self.is_sending_active:
            self.is_sending_active = False
            self.btn_send.configure(text="WYŚLIJ ROZKAZ", fg_color="#D35400")
            return

        if not self.ser or not self.ser.is_open:
            messagebox.showwarning("Błąd", "Najpierw połącz się z urządzeniem!")
            return

        selection = self.tx_combo.get()
        if not selection or selection == "Brak zapisanych funkcji":
            return

        try:
            count = int(self.entry_repeat.get())
            interval_ms = int(self.entry_interval.get())
            if count < 1 or interval_ms < 0: raise ValueError
        except:
            messagebox.showerror("Błąd", "Nieprawidłowa liczba powtórzeń lub odstęp!")
            return

        target_id = selection.split("]")[0].replace("[", "")
        data_to_send = None

        if target_id in self.function_labels:
            mappings = self.function_labels[target_id].get("mappings", {})
            for d_str, f_name in mappings.items():
                check_str = f"[{target_id}] {f_name} ({self.function_labels[target_id].get('device', '?')})"
                if check_str == selection:
                    data_to_send = d_str
                    break

        if data_to_send:
            self.is_sending_active = True
            self.btn_send.configure(text="ZATRZYMAJ", fg_color="#C0392B")
            threading.Thread(target=self._sending_loop, args=(target_id, data_to_send, count, interval_ms),
                             daemon=True).start()
        else:
            messagebox.showerror("Błąd", "Nie znaleziono danych dla tej funkcji.")

    def _sending_loop(self, target_id, data_str, count, interval_ms):
        command = f"SEND:{target_id}|{data_str}\n"
        encoded_cmd = command.encode('utf-8')

        for i in range(count):
            if not self.is_sending_active or not self.is_sniffing:
                break

            try:
                self.ser.write(encoded_cmd)
            except (serial.SerialException, OSError):
                # Błąd zapisu (np. wyrwanie kabla podczas nadawania)
                self.is_sending_active = False
                break
            except Exception as e:
                print(f"TX Error: {e}")
                break

            time.sleep(interval_ms / 1000.0)

        self.is_sending_active = False
        self.after(0, lambda: self.btn_send.configure(text="WYŚLIJ ROZKAZ", fg_color="#D35400"))

    # --- Reszta metod bez zmian ---
    def update_monitor(self, can_id, rtr, ide, dlc, bytes_list):
        data_str = " ".join(bytes_list)
        if can_id not in self.can_rows:
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

            rtr_l = ctk.CTkLabel(self.scroll, text=rtr, fg_color=hi_bg);
            rtr_l.grid(row=row, column=3, padx=2, pady=1)
            ide_l = ctk.CTkLabel(self.scroll, text=ide, fg_color=hi_bg);
            ide_l.grid(row=row, column=4, padx=2, pady=1)
            dlc_l = ctk.CTkLabel(self.scroll, text=dlc, fg_color=hi_bg);
            dlc_l.grid(row=row, column=5, padx=2, pady=1)

            b_labels = []
            for j in range(8):
                val = bytes_list[j] if j < len(bytes_list) else "00"
                l = ctk.CTkLabel(self.scroll, text=val, width=40, fg_color=hi_bg)
                l.grid(row=row, column=6 + j, padx=2, pady=1)
                b_labels.append(l)

            btn = ctk.CTkButton(self.scroll, text="+", width=40, command=lambda cid=can_id: self._save_function(cid))
            btn.grid(row=row, column=14, padx=5)

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
            self._update_tx_list()

    def win_manage_ids(self):
        win = ctk.CTkToplevel(self)
        win.title("Zarządzanie ID")
        win.geometry("500x500")
        win.attributes("-topmost", True)
        tree = ttk.Treeview(win, columns=("id", "name"), show='headings')
        tree.heading("id", text="ID (Hex)");
        tree.heading("name", text="Nazwa Urządzenia")
        tree.column("id", width=100, anchor="center");
        tree.column("name", width=350, anchor="w")
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

        f = ctk.CTkFrame(win)
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
                        current_data_on_screen = " ".join(self.can_rows[cid]['last_data'])
                        if current_data_on_screen == d_str: self.can_rows[cid]['func_lbl'].configure(text=new_func,
                                                                                                     text_color="#F1C40F")
                    reload();
                    self._update_tx_list()
            else:
                messagebox.showinfo("Info", "Zaznacz wiersz do edycji.")

        f = ctk.CTkFrame(win)
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

    def _clear_monitor(self):
        for r in self.can_rows.values():
            for w in r['widgets']: w.destroy()
        self.can_rows.clear()
        self.row_counter = 1


if __name__ == "__main__":
    app = ModernCANApp()
    app.mainloop()