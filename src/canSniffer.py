import serial
import serial.tools.list_ports
import threading
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import time
import queue
import csv
from datetime import datetime
from typing import Dict, List, Optional

# --- PROJECT SETTINGS ---
BAUD = 115200
DB_IDS = 'deciphered_ids.json'
DB_FUNCTIONS = 'function_codes.json'
MAX_ALL_ROWS = 100

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# --- COLOR SCHEME (Modern Design System) ---
class Colors:
    PRIMARY = "#3B82F6"      # Blue
    SUCCESS = "#10B981"      # Emerald
    WARNING = "#F59E0B"      # Amber
    DANGER = "#EF4444"       # Red
    INFO = "#06B6D4"         # Cyan
    SECONDARY = "#6366F1"    # Indigo

    BG_DARK = "#0F172A"      # Slate 900
    BG_MEDIUM = "#1E293B"    # Slate 800
    BG_LIGHT = "#334155"     # Slate 700

    TEXT_PRIMARY = "#F1F5F9" # Slate 100
    TEXT_SECONDARY = "#94A3B8"# Slate 400
    TEXT_MUTED = "#64748B"   # Slate 500


class ModernCANApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CAN Sniffer")
        self.geometry("1920x1080")
        self.minsize(1400, 700)

        # Data structures
        self.can_rows: Dict = {}
        self.all_msgs_widgets: List = []
        self.can_queue = queue.Queue()
        self.session_log: List = []

        # Statistics
        self.stats = {
            'total_frames': 0,
            'frames_per_id': {},
            'start_time': None,
            'last_update': datetime.now()
        }

        # Load databases
        self.id_labels = self._load_db(DB_IDS)
        self.function_labels = self._load_db(DB_FUNCTIONS)

        self.message_queue = []
        self.is_queue_running = False

        # Counters
        self.row_counter_grouped = 1
        self.row_counter_all = 1

        # Connection state
        self.ser: Optional[serial.Serial] = None
        self.is_sniffing = False
        self.is_sending_active = False
        self.is_paused = False

        # Filter state
        self.filter_id = ""

        # ADD THIS:
        self.sort_newest_first = False  # False = oldest first (default), True = newest first
        # Playback state (NEW)
        self.is_playing_back = False
        self.playback_thread = None
        self.loaded_session = []

        # Session start timestamp for relative time (NEW)
        self.session_start_time: Optional[datetime] = None

        # Window close handler
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        self._build_modern_ui()
        self._update_tx_list()
        self.after(10, self._process_queue)
        self.after(1000, self._update_stats_display)

    def _on_closing(self):
        """Clean up resources on window close"""
        self.is_sniffing = False
        self.is_playing_back = False
        if self.ser and self.ser.is_open:
            try:
                self.ser.close()
            except:
                pass
        self.destroy()

    def _load_db(self, path: str) -> Dict:
        """Load JSON database with error handling"""
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading {path}: {e}")
                return {}
        return {}

    def _save_db(self, path: str, data: Dict):
        """Save JSON database"""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save {path}:\n{str(e)}")

    def _build_modern_ui(self):
        """Build modern, clean UI with better layout"""
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ===== LEFT SIDEBAR =====
        self.sidebar = ctk.CTkFrame(self, width=280, fg_color=Colors.BG_DARK, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Header with logo/title
        header = ctk.CTkFrame(self.sidebar, fg_color=Colors.PRIMARY, corner_radius=0, height=60)
        header.pack(fill="x", pady=(0, 20))
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text="⚡ CAN Sniffer",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="white"
        ).pack(pady=15)

        # Connection Section
        self._build_connection_section()

        # Separator
        ctk.CTkFrame(self.sidebar, height=2, fg_color=Colors.BG_LIGHT).pack(fill="x", padx=20, pady=15)

        # Controls Section
        self._build_controls_section()

        # Separator
        ctk.CTkFrame(self.sidebar, height=2, fg_color=Colors.BG_LIGHT).pack(fill="x", padx=20, pady=15)

        # Tools Section
        self._build_tools_section()

        # Status at bottom
        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color=Colors.BG_MEDIUM, corner_radius=8)
        self.status_frame.pack(side="bottom", fill="x", padx=15, pady=15)

        self.status_lbl = ctk.CTkLabel(
            self.status_frame,
            text="● DISCONNECTED",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.TEXT_MUTED
        )
        self.status_lbl.pack(pady=12)

        self.stats_lbl = ctk.CTkLabel(
            self.status_frame,
            text="0 frames | 0 fps",
            font=ctk.CTkFont(size=11),
            text_color=Colors.TEXT_SECONDARY
        )
        self.stats_lbl.pack(pady=(0, 10))

        # ===== MAIN CONTENT AREA =====
        self.main_content = ctk.CTkFrame(self, fg_color=Colors.BG_MEDIUM, corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_content.grid_rowconfigure(1, weight=1)
        self.main_content.grid_columnconfigure(0, weight=1)

        # Top bar with tabs and controls
        self._build_top_bar()

        # Content frames
        self._build_content_frames()

        # ===== STATUS BAR AT BOTTOM =====
        self.status_bar = ctk.CTkFrame(self.main_content, fg_color=Colors.BG_DARK, height=35, corner_radius=0)
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        self.status_bar.grid_propagate(False)

        self.status_message = ctk.CTkLabel(
            self.status_bar,
            text="Ready",
            font=ctk.CTkFont(size=18),
            text_color=Colors.TEXT_SECONDARY,
            anchor="w"
        )
        self.status_message.pack(side="left", padx=15, pady=8)

    def _show_status(self, message: str, duration: int = 3000, color: str = Colors.TEXT_SECONDARY):
        """Show a temporary status message in the status bar"""
        self.status_message.configure(text=message, text_color=color)

        # Auto-clear after duration
        def clear_status():
            try:
                if self.status_message.cget("text") == message:  # Only clear if message hasn't changed
                    self.status_message.configure(text="Ready", text_color=Colors.TEXT_SECONDARY)
            except:
                pass

        self.after(duration, clear_status)

    def _build_connection_section(self):
        """Build connection controls"""
        section = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        section.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(
            section,
            text="CONNECTION",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=Colors.TEXT_SECONDARY
        ).pack(anchor="w", pady=(0, 10))

        # Port selection
        port_frame = ctk.CTkFrame(section, fg_color=Colors.BG_MEDIUM, corner_radius=8)
        port_frame.pack(fill="x", pady=(0, 10))

        self.port_combo = ctk.CTkComboBox(
            port_frame,
            width=260,
            fg_color=Colors.BG_LIGHT,
            border_color=Colors.BG_LIGHT,
            button_color=Colors.PRIMARY,
            button_hover_color=Colors.SECONDARY
        )
        self.port_combo.pack(side="left", padx=10, pady=10)

        self.btn_refresh = ctk.CTkButton(
            port_frame,
            text="↻",
            width=35,
            height=35,
            command=self.refresh_ports,
            fg_color=Colors.INFO,
            hover_color="#0891B2",
            corner_radius=8
        )
        self.btn_refresh.pack(side="left", padx=(0, 10), pady=10)

        self.refresh_ports()

        # Connect button
        self.btn_connect = ctk.CTkButton(
            section,
            text="CONNECT",
            command=self.toggle_connection,
            fg_color=Colors.SUCCESS,
            hover_color="#059669",
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8
        )
        self.btn_connect.pack(fill="x", pady=(0, 10))

        # Pause button
        self.btn_pause = ctk.CTkButton(
            section,
            text="⏸ PAUSE",
            command=self.toggle_pause,
            fg_color=Colors.WARNING,
            hover_color="#D97706",
            height=36,
            state="disabled",
            corner_radius=8
        )
        self.btn_pause.pack(fill="x")

    def _build_controls_section(self):
        """Build transmission controls"""
        section = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        section.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(
            section,
            text="TRANSMIT",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=Colors.TEXT_SECONDARY
        ).pack(anchor="w", pady=(0, 10))

        # Quick send frame
        quick_frame = ctk.CTkFrame(section, fg_color=Colors.BG_MEDIUM, corner_radius=8)
        quick_frame.pack(fill="x", pady=(0, 10))
        quick_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(quick_frame, text="Quick Send:", text_color=Colors.TEXT_SECONDARY).grid(
            row=0, column=0, columnspan=2, padx=10, pady=(8, 5), sticky="w"
        )

        self.tx_combo = ctk.CTkComboBox(
            quick_frame,
            values=["No functions saved"],
            fg_color=Colors.BG_LIGHT,
            border_color=Colors.BG_LIGHT,
            button_color=Colors.PRIMARY,
            corner_radius=8
        )
        self.tx_combo.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="Send Once",
            command=self.send_once,
            fg_color=Colors.SECONDARY,
            hover_color="#4F46E5",
            height=32
        ).grid(row=2, column=0, padx=(10, 5), pady=(5, 10), sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="Add to Queue",
            command=self.add_to_queue,
            fg_color=Colors.INFO,
            hover_color="#0891B2",
            height=32
        ).grid(row=2, column=1, padx=(5, 10), pady=(5, 10), sticky="ew")

        # Queue management
        ctk.CTkButton(
            section,
            text="📋 Manage Queue",
            command=self.open_queue_manager,
            fg_color=Colors.PRIMARY,
            hover_color=Colors.SECONDARY,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8
        ).pack(fill="x")
        ctk.CTkButton(
            section,
            text="✏️ Manual Transmit",
            command=self.open_manual_transmit,
            fg_color=Colors.WARNING,
            hover_color="#D97706",
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8
        ).pack(fill="x", pady=(5, 0))

    def _build_tools_section(self):
        """Build tools section"""
        section = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        section.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(
            section,
            text="TOOLS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=Colors.TEXT_SECONDARY
        ).pack(anchor="w", pady=(0, 10))

        # Tool buttons
        tools = [
            ("📊 Statistics", self.show_statistics, Colors.SECONDARY),
            ("💾 Export CSV", self.export_session_log, Colors.INFO),
            ("📂 Load Session", self.load_session_file, Colors.INFO),  # NEW
            ("▶️ Playback Session", self.open_playback_dialog, Colors.SUCCESS),  # NEW
            ("🏷️ Manage IDs", self.win_manage_ids, Colors.PRIMARY),
            ("⚙️ Manage Functions", self.win_manage_funcs, Colors.PRIMARY),
            ("🗑️ Clear Monitor", self._clear_monitor, Colors.DANGER),
        ]

        for text, command, color in tools:
            ctk.CTkButton(
                section,
                text=text,
                command=command,
                fg_color=color,
                hover_color=self._darken_color(color),
                height=36,
                corner_radius=8,
                anchor="w",
                font=ctk.CTkFont(size=12)
            ).pack(fill="x", pady=3)

    def _build_top_bar(self):
        """Build top bar with tabs and filter"""
        top_bar = ctk.CTkFrame(self.main_content, fg_color=Colors.BG_DARK, height=60, corner_radius=0)
        top_bar.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        top_bar.grid_propagate(False)

        # View mode tabs
        self.view_mode = ctk.StringVar(value="Grouped")
        self.seg_view = ctk.CTkSegmentedButton(
            top_bar,
            values=["Grouped", "Stream"],
            command=self.toggle_view_mode,
            variable=self.view_mode,
            fg_color=Colors.BG_MEDIUM,
            selected_color=Colors.PRIMARY,
            selected_hover_color=Colors.SECONDARY,
            unselected_color=Colors.BG_LIGHT,
            unselected_hover_color=Colors.BG_MEDIUM
        )
        self.seg_view.pack(side="left", padx=20, pady=15)

        # ADD SORT BUTTON HERE (between tabs and filters):
        self.btn_sort = ctk.CTkButton(
            top_bar,
            text="▼ Oldest First",
            width=130,
            command=self.toggle_sort_order,
            fg_color=Colors.INFO,
            hover_color="#0891B2",
            corner_radius=8
        )
        self.btn_sort.pack(side="left", padx=(0, 20), pady=15)

        # Filter controls
        filter_frame = ctk.CTkFrame(top_bar, fg_color="transparent")
        filter_frame.pack(side="right", padx=20, pady=15)

        ctk.CTkLabel(filter_frame, text="🔍", font=ctk.CTkFont(size=16)).pack(side="left", padx=(0, 5))

        # ID Filter
        self.filter_entry = ctk.CTkEntry(
            filter_frame,
            placeholder_text="Filter by ID...",
            width=120,
            fg_color=Colors.BG_MEDIUM,
            border_color=Colors.BG_LIGHT
        )
        self.filter_entry.pack(side="left", padx=5)

        # Advanced filters button
        ctk.CTkButton(
            filter_frame,
            text="⚙ Filters",
            width=80,
            command=self._open_advanced_filters,
            fg_color=Colors.SECONDARY,
            hover_color="#4F46E5"
        ).pack(side="left", padx=5)

    def toggle_sort_order(self):
        """Toggle between newest first and oldest first"""
        self.sort_newest_first = not self.sort_newest_first

        if self.sort_newest_first:
            self.btn_sort.configure(text="▲ Newest First")
        else:
            self.btn_sort.configure(text="▼ Oldest First")

        # Rebuild current view
        current_mode = self.view_mode.get()
        if current_mode == "Grouped":
            self._rebuild_grouped_view()
        else:
            self._rebuild_stream_view()

    def _rebuild_grouped_view(self):
        """Rebuild grouped view with current sort order"""
        # Store current data
        stored_rows = {}
        for can_id, row_data in self.can_rows.items():
            stored_rows[can_id] = {
                'last_data': row_data['last_data'].copy(),
                'dev_name': row_data['dev_lbl'].cget("text"),
                'func_name': row_data['func_lbl'].cget("text"),
                'timestamp': row_data.get('timestamp', 0.0)  # NEW
            }

        # Clear display
        for r in self.can_rows.values():
            for w in r['widgets']:
                try:
                    w.destroy()
                except:
                    pass
        self.can_rows.clear()

        # Sort IDs
        sorted_ids = sorted(stored_rows.keys())
        if self.sort_newest_first:
            sorted_ids = reversed(sorted_ids)

        # Rebuild in new order
        self.row_counter_grouped = 1
        for can_id in sorted_ids:
            data = stored_rows[can_id]
            dev_name = data['dev_name']
            func_name = data['func_name']
            bytes_list = data['last_data']
            timestamp = data['timestamp']  # NEW

            # Create row
            row = self.row_counter_grouped
            self.row_counter_grouped += 1
            bg = Colors.BG_DARK

            # NEW: Timestamp label
            time_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=f"{timestamp:.3f}",
                text_color=Colors.TEXT_MUTED,
                width=70,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            time_l.grid(row=row, column=0, padx=4, pady=4, sticky="ew")

            id_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=can_id,
                text_color=Colors.PRIMARY,
                cursor="hand2",
                width=60,
                fg_color=bg,
                font=ctk.CTkFont(size=11, weight="bold")
            )
            id_l.grid(row=row, column=1, padx=4, pady=4, sticky="ew")
            id_l.bind("<Button-1>", lambda e, cid=can_id: self._open_id_edit(cid))

            dev_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=dev_name,
                text_color=Colors.SUCCESS if dev_name != "Unknown" else Colors.TEXT_MUTED,
                width=100,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            dev_l.grid(row=row, column=2, padx=4, pady=4, sticky="ew")

            func_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=func_name,
                text_color=Colors.WARNING if func_name != "---" else Colors.TEXT_MUTED,
                width=120,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            func_l.grid(row=row, column=3, padx=4, pady=4, sticky="ew")

            rtr_l = ctk.CTkLabel(self.scroll_grouped, text="0", text_color=Colors.TEXT_SECONDARY, width=35, fg_color=bg,
                                 font=ctk.CTkFont(size=11))
            rtr_l.grid(row=row, column=4, padx=4, pady=4, sticky="ew")

            ide_l = ctk.CTkLabel(self.scroll_grouped, text="0", text_color=Colors.TEXT_SECONDARY, width=35, fg_color=bg,
                                 font=ctk.CTkFont(size=11))
            ide_l.grid(row=row, column=5, padx=4, pady=4, sticky="ew")

            dlc_l = ctk.CTkLabel(self.scroll_grouped, text="8", text_color=Colors.TEXT_SECONDARY, width=35, fg_color=bg,
                                 font=ctk.CTkFont(size=11))
            dlc_l.grid(row=row, column=6, padx=4, pady=4, sticky="ew")

            # Data bytes
            b_labels = []
            for j in range(8):
                val = bytes_list[j] if j < len(bytes_list) else "00"
                color = Colors.DANGER if val != "00" else Colors.TEXT_MUTED
                l = ctk.CTkLabel(
                    self.scroll_grouped,
                    text=val,
                    text_color=color,
                    width=45,
                    fg_color=bg,
                    font=ctk.CTkFont(size=11)
                )
                l.grid(row=row, column=7 + j, padx=4, pady=4, sticky="ew")
                b_labels.append(l)

            btn = ctk.CTkButton(
                self.scroll_grouped,
                text="+",
                width=40,
                height=28,
                command=lambda cid=can_id: self._save_function(cid),
                fg_color=Colors.SUCCESS,
                hover_color="#059669",
                corner_radius=6,
                font=ctk.CTkFont(size=14, weight="bold")
            )
            btn.grid(row=row, column=15, padx=4, pady=4)

            widgets = [time_l, id_l, dev_l, func_l, rtr_l, ide_l, dlc_l] + b_labels
            self.can_rows[can_id] = {
                'time_lbl': time_l,  # NEW
                'dev_lbl': dev_l,
                'func_lbl': func_l,
                'bytes': b_labels,
                'last_data': bytes_list.copy(),
                'widgets': widgets + [btn],
                'bg': bg,
                'timestamp': timestamp  # NEW
            }

    def _rebuild_stream_view(self):
        """Rebuild stream view with current sort order"""
        # Store current messages
        stored_messages = []
        for widgets in self.all_msgs_widgets:
            if len(widgets) >= 15:  # Ensure we have all widgets
                try:
                    msg_data = {
                        'id': widgets[0].cget("text"),
                        'device': widgets[1].cget("text"),
                        'function': widgets[2].cget("text"),
                        'rtr': widgets[3].cget("text"),
                        'ide': widgets[4].cget("text"),
                        'dlc': widgets[5].cget("text"),
                        'bytes': [widgets[6 + i].cget("text") for i in range(8)],
                        'time': widgets[14].cget("text")
                    }
                    stored_messages.append(msg_data)
                except:
                    pass

        # Clear display
        for row_widgets in self.all_msgs_widgets:
            for w in row_widgets:
                try:
                    w.destroy()
                except:
                    pass
        self.all_msgs_widgets.clear()

        # Reverse if newest first
        if self.sort_newest_first:
            stored_messages = list(reversed(stored_messages))

        # Rebuild
        self.row_counter_all = 1
        for msg in stored_messages:
            row = self.row_counter_all
            self.row_counter_all += 1
            bg = Colors.BG_MEDIUM if row % 2 == 0 else Colors.BG_DARK

            widgets = []

            def add_lbl(txt, col, color=Colors.TEXT_PRIMARY, width=50):
                l = ctk.CTkLabel(
                    self.scroll_all,
                    text=txt,
                    fg_color=bg,
                    text_color=color,
                    width=width,
                    anchor="w",
                    font=ctk.CTkFont(size=11)
                )
                l.grid(row=row, column=col, padx=4, pady=1, sticky="ew")
                widgets.append(l)

            add_lbl(msg['id'], 0, Colors.PRIMARY, 80)
            add_lbl(msg['device'], 1, Colors.SUCCESS if msg['device'] != "Unknown" else Colors.TEXT_MUTED, 120)
            add_lbl(msg['function'], 2, Colors.WARNING if msg['function'] != "---" else Colors.TEXT_MUTED, 150)
            add_lbl(msg['rtr'], 3, Colors.TEXT_SECONDARY, 40)
            add_lbl(msg['ide'], 4, Colors.TEXT_SECONDARY, 40)
            add_lbl(msg['dlc'], 5, Colors.TEXT_SECONDARY, 40)

            for j in range(8):
                val = msg['bytes'][j]
                color = Colors.DANGER if val != "00" else Colors.TEXT_MUTED
                add_lbl(val, 6 + j, color, 40)

            add_lbl(msg['time'], 14, Colors.TEXT_MUTED, 80)

            # Add save button
            data_str = " ".join(msg['bytes'])
            btn = ctk.CTkButton(
                self.scroll_all,
                text="+",
                width=30,
                height=24,
                command=lambda cid=msg['id'], ds=data_str: self._save_function_stream(cid, ds),
                fg_color=Colors.SUCCESS,
                hover_color="#059669",
                corner_radius=6,
                font=ctk.CTkFont(size=12, weight="bold")
            )
            btn.grid(row=row, column=15, padx=4, pady=1)
            widgets.append(btn)

            self.all_msgs_widgets.append(widgets)

    def _open_advanced_filters(self):
        """Open advanced filtering options"""
        win = ctk.CTkToplevel(self)
        win.title("Advanced Filters")
        win.geometry("400x500")
        win.attributes("-topmost", True)
        win.configure(fg_color=Colors.BG_DARK)

        # Initialize filter settings if not exists
        if not hasattr(self, 'filter_settings'):
            self.filter_settings = {
                'hide_periodic': False,
                'hide_zero_data': False,
                'show_only_changed': False,
                'min_dlc': 0,
                'max_dlc': 8,
                'id_whitelist': [],
                'id_blacklist': []
            }

        main_frame = ctk.CTkFrame(win, fg_color=Colors.BG_DARK)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="Filter Options",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(pady=(0, 20))

        # Checkboxes for quick filters
        self.hide_periodic_var = ctk.BooleanVar(value=self.filter_settings['hide_periodic'])
        ctk.CTkCheckBox(
            main_frame,
            text="Hide periodic messages (heartbeats)",
            variable=self.hide_periodic_var,
            fg_color=Colors.PRIMARY,
            hover_color=Colors.SECONDARY
        ).pack(anchor="w", pady=5)

        self.hide_zero_var = ctk.BooleanVar(value=self.filter_settings['hide_zero_data'])
        ctk.CTkCheckBox(
            main_frame,
            text="Hide messages with all-zero data",
            variable=self.hide_zero_var,
            fg_color=Colors.PRIMARY,
            hover_color=Colors.SECONDARY
        ).pack(anchor="w", pady=5)

        self.show_changed_var = ctk.BooleanVar(value=self.filter_settings['show_only_changed'])
        ctk.CTkCheckBox(
            main_frame,
            text="Show only messages that changed recently",
            variable=self.show_changed_var,
            fg_color=Colors.PRIMARY,
            hover_color=Colors.SECONDARY
        ).pack(anchor="w", pady=5)

        # DLC Range
        ctk.CTkLabel(main_frame, text="DLC Range:", text_color=Colors.TEXT_SECONDARY).pack(anchor="w", pady=(15, 5))

        dlc_frame = ctk.CTkFrame(main_frame, fg_color=Colors.BG_MEDIUM)
        dlc_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(dlc_frame, text="Min:").pack(side="left", padx=(10, 5))
        self.min_dlc_entry = ctk.CTkEntry(dlc_frame, width=50, fg_color=Colors.BG_LIGHT)
        self.min_dlc_entry.insert(0, str(self.filter_settings['min_dlc']))
        self.min_dlc_entry.pack(side="left", padx=5)

        ctk.CTkLabel(dlc_frame, text="Max:").pack(side="left", padx=(20, 5))
        self.max_dlc_entry = ctk.CTkEntry(dlc_frame, width=50, fg_color=Colors.BG_LIGHT)
        self.max_dlc_entry.insert(0, str(self.filter_settings['max_dlc']))
        self.max_dlc_entry.pack(side="left", padx=5)

        # ID Lists
        ctk.CTkLabel(main_frame, text="Whitelist IDs (comma-separated):",
                     text_color=Colors.TEXT_SECONDARY).pack(anchor="w", pady=(15, 5))
        self.whitelist_entry = ctk.CTkEntry(main_frame, fg_color=Colors.BG_MEDIUM)
        self.whitelist_entry.insert(0, ",".join(self.filter_settings['id_whitelist']))
        self.whitelist_entry.pack(fill="x", pady=5)

        ctk.CTkLabel(main_frame, text="Blacklist IDs (comma-separated):",
                     text_color=Colors.TEXT_SECONDARY).pack(anchor="w", pady=(15, 5))
        self.blacklist_entry = ctk.CTkEntry(main_frame, fg_color=Colors.BG_MEDIUM)
        self.blacklist_entry.insert(0, ",".join(self.filter_settings['id_blacklist']))
        self.blacklist_entry.pack(fill="x", pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(pady=(20, 0))

        def apply_filters():
            self.filter_settings['hide_periodic'] = self.hide_periodic_var.get()
            self.filter_settings['hide_zero_data'] = self.hide_zero_var.get()
            self.filter_settings['show_only_changed'] = self.show_changed_var.get()

            try:
                self.filter_settings['min_dlc'] = int(self.min_dlc_entry.get())
                self.filter_settings['max_dlc'] = int(self.max_dlc_entry.get())
            except:
                pass

            whitelist = self.whitelist_entry.get().strip()
            self.filter_settings['id_whitelist'] = [x.strip().upper() for x in whitelist.split(",") if x.strip()]

            blacklist = self.blacklist_entry.get().strip()
            self.filter_settings['id_blacklist'] = [x.strip().upper() for x in blacklist.split(",") if x.strip()]

            self._show_status("✓ Filters applied", 3000, Colors.SUCCESS)
            win.destroy()

        def reset_filters():
            self.filter_settings = {
                'hide_periodic': False,
                'hide_zero_data': False,
                'show_only_changed': False,
                'min_dlc': 0,
                'max_dlc': 8,
                'id_whitelist': [],
                'id_blacklist': []
            }
            self._show_status("✓ Filters reset", 3000, Colors.INFO)
            win.destroy()

        ctk.CTkButton(btn_frame, text="Apply", command=apply_filters,
                      fg_color=Colors.SUCCESS, width=120).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Reset", command=reset_filters,
                      fg_color=Colors.DANGER, width=120).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=win.destroy,
                      fg_color=Colors.BG_LIGHT, width=120).pack(side="left", padx=5)

    def send_once(self):
        """Send selected message once"""
        if not self.ser or not self.ser.is_open:
            self._show_status("⚠ No connection!", 3000, Colors.WARNING)
            return

        selection = self.tx_combo.get()
        if not selection or selection == "No functions saved":
            return

        target_id = selection.split("]")[0].replace("[", "")
        data_to_send = None

        if target_id in self.function_labels:
            mappings = self.function_labels[target_id].get("mappings", {})
            for d_str, f_name in mappings.items():
                if f"[{target_id}] {f_name}" in selection:
                    data_to_send = d_str
                    break

        if data_to_send:
            command = f"SEND:{target_id}|{data_to_send}\n"
            try:
                self.ser.write(command.encode('utf-8'))
                self._show_status(f"✓ Sent: {target_id}", 2000, Colors.SUCCESS)
            except Exception as e:
                self._show_status(f"✗ Send failed: {e}", 3000, Colors.DANGER)

    def add_to_queue(self):
        """Add selected message to queue with custom parameters"""
        selection = self.tx_combo.get()
        if not selection or selection == "No functions saved":
            return

        target_id = selection.split("]")[0].replace("[", "")
        data_to_send = None
        func_name = ""

        if target_id in self.function_labels:
            mappings = self.function_labels[target_id].get("mappings", {})
            for d_str, f_name in mappings.items():
                if f"[{target_id}] {f_name}" in selection:
                    data_to_send = d_str
                    func_name = f_name
                    break

        if data_to_send:
            # Create dialog for parameters
            dialog = ctk.CTkToplevel(self)
            dialog.title("Add to Queue")
            dialog.geometry("350x300")
            dialog.attributes("-topmost", True)
            dialog.configure(fg_color=Colors.BG_DARK)
            dialog.grab_set()

            main_frame = ctk.CTkFrame(dialog, fg_color=Colors.BG_DARK)
            main_frame.pack(fill="both", expand=True, padx=20, pady=20)

            ctk.CTkLabel(
                main_frame,
                text=f"Add: [{target_id}] {func_name}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=Colors.PRIMARY
            ).pack(pady=(0, 20))

            # Repeat count
            ctk.CTkLabel(main_frame, text="Repeat count:", text_color=Colors.TEXT_SECONDARY).pack(anchor="w",
                                                                                                  pady=(0, 5))
            repeat_entry = ctk.CTkEntry(main_frame, fg_color=Colors.BG_MEDIUM)
            repeat_entry.insert(0, "1")
            repeat_entry.pack(fill="x", pady=(0, 15))

            # Delay
            ctk.CTkLabel(main_frame, text="Delay between repeats (ms):", text_color=Colors.TEXT_SECONDARY).pack(
                anchor="w", pady=(0, 5))
            delay_entry = ctk.CTkEntry(main_frame, fg_color=Colors.BG_MEDIUM)
            delay_entry.insert(0, "100")
            delay_entry.pack(fill="x", pady=(0, 20))

            def add():
                try:
                    repeat = int(repeat_entry.get())
                    delay = int(delay_entry.get())

                    self.message_queue.append({
                        'id': target_id,
                        'data': data_to_send,
                        'name': func_name,
                        'repeat': repeat,
                        'delay': delay
                    })
                    self._show_status(f"✓ Added to queue: {func_name}", 2000, Colors.SUCCESS)
                    dialog.destroy()
                except ValueError:
                    self._show_status("✗ Invalid numbers!", 3000, Colors.DANGER)

            btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
            btn_frame.pack()

            ctk.CTkButton(btn_frame, text="Add", command=add, fg_color=Colors.SUCCESS, width=120).pack(side="left",
                                                                                                       padx=5)
            ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy, fg_color=Colors.BG_LIGHT, width=120).pack(
                side="left", padx=5)

    def open_queue_manager(self):
        """Open queue management window"""
        win = ctk.CTkToplevel(self)
        win.title("Message Queue")
        win.geometry("700x500")
        win.attributes("-topmost", True)
        win.configure(fg_color=Colors.BG_DARK)

        main_frame = ctk.CTkFrame(win, fg_color=Colors.BG_DARK)
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Header
        header = ctk.CTkFrame(main_frame, fg_color=Colors.BG_MEDIUM)
        header.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            header,
            text=f"Message Queue ({len(self.message_queue)} messages)",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=10)

        # Queue list
        list_frame = ctk.CTkScrollableFrame(main_frame, fg_color=Colors.BG_MEDIUM)
        list_frame.pack(fill="both", expand=True, pady=(0, 10))

        def refresh_queue():
            for widget in list_frame.winfo_children():
                widget.destroy()

            if not self.message_queue:
                ctk.CTkLabel(
                    list_frame,
                    text="Queue is empty",
                    text_color=Colors.TEXT_MUTED
                ).pack(pady=20)
                return

            for idx, msg in enumerate(self.message_queue):
                msg_frame = ctk.CTkFrame(list_frame, fg_color=Colors.BG_DARK, corner_radius=8)
                msg_frame.pack(fill="x", pady=5, padx=5)

                # Message info
                info_frame = ctk.CTkFrame(msg_frame, fg_color="transparent")
                info_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

                ctk.CTkLabel(
                    info_frame,
                    text=f"#{idx + 1}: [{msg['id']}] {msg['name']}",
                    font=ctk.CTkFont(weight="bold"),
                    text_color=Colors.PRIMARY
                ).pack(anchor="w")

                ctk.CTkLabel(
                    info_frame,
                    text=f"Data: {msg['data']} | Repeat: {msg['repeat']}x | Delay: {msg['delay']}ms",
                    text_color=Colors.TEXT_SECONDARY,
                    font=ctk.CTkFont(size=10)
                ).pack(anchor="w")

                # Buttons
                btn_frame = ctk.CTkFrame(msg_frame, fg_color="transparent")
                btn_frame.pack(side="right", padx=10)

                ctk.CTkButton(
                    btn_frame,
                    text="↑",
                    width=30,
                    command=lambda i=idx: move_up(i),
                    fg_color=Colors.INFO
                ).pack(side="left", padx=2)

                ctk.CTkButton(
                    btn_frame,
                    text="↓",
                    width=30,
                    command=lambda i=idx: move_down(i),
                    fg_color=Colors.INFO
                ).pack(side="left", padx=2)

                ctk.CTkButton(
                    btn_frame,
                    text="✎",
                    width=30,
                    command=lambda i=idx: edit_message(i),
                    fg_color=Colors.WARNING
                ).pack(side="left", padx=2)

                ctk.CTkButton(
                    btn_frame,
                    text="✕",
                    width=30,
                    command=lambda i=idx: delete_message(i),
                    fg_color=Colors.DANGER
                ).pack(side="left", padx=2)

        def move_up(idx):
            if idx > 0:
                self.message_queue[idx], self.message_queue[idx - 1] = \
                    self.message_queue[idx - 1], self.message_queue[idx]
                refresh_queue()

        def move_down(idx):
            if idx < len(self.message_queue) - 1:
                self.message_queue[idx], self.message_queue[idx + 1] = \
                    self.message_queue[idx + 1], self.message_queue[idx]
                refresh_queue()

        def delete_message(idx):
            self.message_queue.pop(idx)
            refresh_queue()

        def edit_message(idx):
            msg = self.message_queue[idx]
            edit_win = ctk.CTkToplevel(win)
            edit_win.title("Edit Message")
            edit_win.geometry("350x200")
            edit_win.configure(fg_color=Colors.BG_DARK)

            ctk.CTkLabel(edit_win, text="Repeat count:").pack(pady=(20, 5))
            repeat_entry = ctk.CTkEntry(edit_win)
            repeat_entry.insert(0, str(msg['repeat']))
            repeat_entry.pack(pady=5)

            ctk.CTkLabel(edit_win, text="Delay (ms):").pack(pady=5)
            delay_entry = ctk.CTkEntry(edit_win)
            delay_entry.insert(0, str(msg['delay']))
            delay_entry.pack(pady=5)

            def save():
                try:
                    msg['repeat'] = int(repeat_entry.get())
                    msg['delay'] = int(delay_entry.get())
                    refresh_queue()
                    edit_win.destroy()
                except:
                    pass

            ctk.CTkButton(edit_win, text="Save", command=save, fg_color=Colors.SUCCESS).pack(pady=20)

        refresh_queue()

        # Control buttons
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x")

        self.queue_status_label = ctk.CTkLabel(
            btn_frame,
            text="Ready",
            text_color=Colors.TEXT_SECONDARY
        )
        self.queue_status_label.pack(side="left", padx=10)

        def run_queue():
            if not self.ser or not self.ser.is_open:
                self._show_status("⚠ No connection!", 3000, Colors.WARNING)
                return

            if not self.message_queue:
                self._show_status("⚠ Queue is empty!", 3000, Colors.WARNING)
                return

            self.is_queue_running = True
            threading.Thread(target=self._execute_queue, daemon=True).start()

        def stop_queue():
            self.is_queue_running = False

        def clear_queue():
            self.message_queue.clear()
            refresh_queue()

        ctk.CTkButton(
            btn_frame,
            text="▶ Run Queue",
            command=run_queue,
            fg_color=Colors.SUCCESS,
            width=120
        ).pack(side="right", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="⏹ Stop",
            command=stop_queue,
            fg_color=Colors.DANGER,
            width=100
        ).pack(side="right", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Clear All",
            command=clear_queue,
            fg_color=Colors.BG_LIGHT,
            width=100
        ).pack(side="right", padx=5)

    def _execute_queue(self):
        """Execute message queue in background thread"""
        self.after(0, lambda: self._show_status("▶ Queue running...", 0, Colors.INFO))

        for msg in self.message_queue:
            if not self.is_queue_running or not self.is_sniffing:
                break

            for _ in range(msg['repeat']):
                if not self.is_queue_running or not self.is_sniffing:
                    break

                command = f"SEND:{msg['id']}|{msg['data']}\n"
                try:
                    self.ser.write(command.encode('utf-8'))
                except:
                    break

                time.sleep(msg['delay'] / 1000.0)

        self.is_queue_running = False
        self.after(0, lambda: self._show_status("✓ Queue completed", 3000, Colors.SUCCESS))

    def _build_content_frames(self):
        """Build content display frames"""
        # Grouped view
        self.scroll_grouped = ctk.CTkScrollableFrame(
            self.main_content,
            fg_color=Colors.BG_DARK,
            corner_radius=0
        )
        self.scroll_grouped.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

        # UPDATED: Added Time column
        headers = ["Time", "ID", "Device", "Function", "RTR", "IDE", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", ""]

        header_frame = ctk.CTkFrame(self.scroll_grouped, fg_color=Colors.BG_MEDIUM, corner_radius=0)
        header_frame.grid(row=0, column=0, columnspan=16, sticky="ew", pady=(0, 2))

        # Define consistent widths for each column type
        column_widths = {
            'time': 70,      # NEW
            'id': 60,
            'device': 100,
            'function': 120,
            'meta': 35,  # RTR, IDE, DLC
            'byte': 45,  # D0-D7
            'button': 40
        }

        for i, h in enumerate(headers):
            if i == 0:       # Time (NEW)
                width = column_widths['time']
            elif i == 1:     # ID
                width = column_widths['id']
            elif i == 2:     # Device
                width = column_widths['device']
            elif i == 3:     # Function
                width = column_widths['function']
            elif i in [4, 5, 6]:  # RTR, IDE, DLC
                width = column_widths['meta']
            elif i >= 7 and i <= 14:  # D0-D7
                width = column_widths['byte']
            else:            # Button column
                width = column_widths['button']

            label = ctk.CTkLabel(
                header_frame,
                text=h,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=Colors.TEXT_SECONDARY,
                width=width
            )
            label.grid(row=0, column=i, padx=4, pady=10, sticky="ew")

        # Stream view (unchanged)
        self.scroll_all = ctk.CTkScrollableFrame(
            self.main_content,
            fg_color=Colors.BG_DARK,
            corner_radius=0
        )

        headers_stream = ["ID", "Device", "Function", "RTR", "IDE", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6",
                          "D7", "Time", ""]

        header_frame_stream = ctk.CTkFrame(self.scroll_all, fg_color=Colors.BG_MEDIUM, corner_radius=0)
        header_frame_stream.grid(row=0, column=0, columnspan=16, sticky="ew", pady=(0, 2))

        for i, h in enumerate(headers_stream):
            if i == 0:  # ID
                width = column_widths['id']
            elif i == 1:  # Device
                width = column_widths['device']
            elif i == 2:  # Function
                width = column_widths['function']
            elif i in [3, 4, 5]:  # RTR, IDE, DLC
                width = column_widths['meta']
            elif i >= 6 and i <= 13:  # D0-D7
                width = column_widths['byte']
            elif i == 14:  # Time
                width = 80
            else:  # Button column
                width = column_widths['button']

            label = ctk.CTkLabel(
                header_frame_stream,
                text=h,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=Colors.TEXT_SECONDARY,
                width=width
            )
            label.grid(row=0, column=i, padx=4, pady=10, sticky="ew")

    def _darken_color(self, hex_color: str) -> str:
        """Darken a hex color by 20%"""
        hex_color = hex_color.lstrip('#')
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
        r, g, b = int(r * 0.8), int(g * 0.8), int(b * 0.8)
        return f"#{r:02x}{g:02x}{b:02x}"

    def toggle_view_mode(self, value: str):
        """Switch between grouped and stream view"""
        if value == "Grouped":
            self.scroll_all.grid_forget()
            self.scroll_grouped.grid(row=1, column=0, sticky="nsew")
        else:
            self.scroll_grouped.grid_forget()
            self.scroll_all.grid(row=1, column=0, sticky="nsew")

    def refresh_ports(self):
        """Refresh available COM ports"""
        ports = [p.device for p in serial.tools.list_ports.comports()]
        if not ports:
            ports = ["No ports found"]
            self.port_combo.set("No ports found")
        else:
            self.port_combo.set(ports[0])
        self.port_combo.configure(values=ports)

    def _update_tx_list(self):
        """Update transmission function list"""
        items = []
        for cid, obj in self.function_labels.items():
            dev_name = obj.get("device", "Unknown")
            for data_pattern, func_name in obj.get("mappings", {}).items():
                items.append(f"[{cid}] {func_name} ({dev_name})")
        if not items:
            items = ["No functions saved"]
        items.sort()
        self.tx_combo.configure(values=items)
        if items:
            self.tx_combo.set(items[0])

    def toggle_connection(self):
        """Toggle serial connection"""
        if not self.is_sniffing:
            selected_port = self.port_combo.get()
            if selected_port == "No ports found" or not selected_port:
                messagebox.showerror("Error", "No COM ports detected!")
                return

            try:
                self.ser = serial.Serial(selected_port, BAUD, timeout=0.1)
                self.is_sniffing = True
                self.is_paused = False

                # Initialize statistics
                self.stats['start_time'] = datetime.now()
                self.stats['last_update'] = datetime.now()
                self.session_log.clear()

                self.session_start_time = datetime.now()

                self.btn_connect.configure(text="DISCONNECT", fg_color=Colors.DANGER)
                self.status_lbl.configure(text="● CONNECTED", text_color=Colors.SUCCESS)
                self.port_combo.configure(state="disabled")
                self.btn_refresh.configure(state="disabled")
                self.btn_pause.configure(state="normal")

                threading.Thread(target=self._serial_listener, daemon=True).start()
            except Exception as e:
                messagebox.showerror("Connection Error", f"Failed to connect:\n{str(e)}")
        else:
            self._disconnect_cleanup()

    def toggle_pause(self):
        """Toggle pause state"""
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.btn_pause.configure(text="▶ RESUME", fg_color=Colors.SUCCESS)
            self.status_lbl.configure(text="● PAUSED", text_color=Colors.WARNING)
        else:
            self.btn_pause.configure(text="⏸ PAUSE", fg_color=Colors.WARNING)
            self.status_lbl.configure(text="● CONNECTED", text_color=Colors.SUCCESS)

    def _disconnect_cleanup(self):
        """Clean up connection"""
        self.is_sniffing = False
        self.is_sending_active = False
        self.is_paused = False

        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None

        self.after(0, lambda: self.btn_connect.configure(text="CONNECT", fg_color=Colors.SUCCESS))
        self.after(0, lambda: self.status_lbl.configure(text="● DISCONNECTED", text_color=Colors.TEXT_MUTED))
        self.after(0, lambda: self.port_combo.configure(state="normal"))
        self.after(0, lambda: self.btn_refresh.configure(state="normal"))
        self.after(0, lambda: self.btn_pause.configure(state="disabled"))

    def _serial_listener(self):
        """Serial port listener thread"""
        print("Serial listener started")
        while self.is_sniffing:
            try:
                if self.ser and self.ser.is_open:
                    if self.ser.in_waiting:
                        try:
                            line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                            if line.startswith("FRAME:"):
                                parts = line.replace("FRAME:", "").split("|")
                                if len(parts) >= 5:
                                    frame_data = {
                                        'id': parts[0].upper(),
                                        'rtr': parts[1],
                                        'ide': parts[2],
                                        'dlc': parts[3],
                                        'data': parts[4].split(" "),
                                        'timestamp': datetime.now()
                                    }
                                    self.can_queue.put(frame_data)
                        except Exception as e:
                            print(f"Parse error: {e}")
                    else:
                        time.sleep(0.005)
                else:
                    break
            except Exception as e:
                print(f"Serial error: {e}")
                self.is_sniffing = False
                self.after(0, self._disconnect_cleanup)
                break
        print("Serial listener stopped")

    def _process_queue(self):
        """Process CAN frames from queue"""
        processed = 0
        try:
            while processed < 50:
                frame = self.can_queue.get_nowait()

                # Update statistics
                self.stats['total_frames'] += 1
                frame_id = frame['id']
                if frame_id not in self.stats['frames_per_id']:
                    self.stats['frames_per_id'][frame_id] = 0
                self.stats['frames_per_id'][frame_id] += 1

                # Add to session log
                self.session_log.append({
                    'timestamp': frame['timestamp'].strftime("%H:%M:%S.%f")[:-3],
                    'id': frame_id,
                    'rtr': frame['rtr'],
                    'ide': frame['ide'],
                    'dlc': frame['dlc'],
                    'data': " ".join(frame['data'])
                })

                # Update monitor if not paused
                if not self.is_paused:
                    self.update_monitor(
                        frame['id'],
                        frame['rtr'],
                        frame['ide'],
                        frame['dlc'],
                        frame['data'],
                        frame['timestamp']  # NEW: pass timestamp
                    )

                processed += 1
        except queue.Empty:
            pass

        self.after(10, self._process_queue)

    def _update_stats_display(self):
        """Update statistics display"""
        if self.is_sniffing and self.stats['start_time']:
            elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
            fps = self.stats['total_frames'] / elapsed if elapsed > 0 else 0
            self.stats_lbl.configure(text=f"{self.stats['total_frames']} frames | {fps:.1f} fps")

        self.after(1000, self._update_stats_display)

    def update_monitor(self, can_id: str, rtr: str, ide: str, dlc: str, bytes_list: List[str], timestamp: datetime = None):
        """Update monitor display with validation"""
        try:
            # Validate DLC
            dlc_int = int(dlc)
            if not (0 <= dlc_int <= 8):
                return

            # Ensure 8 bytes (pad with 00)
            bytes_list = list(bytes_list)
            while len(bytes_list) < 8:
                bytes_list.append("00")
            bytes_list = bytes_list[:8]

            # Validate hex format
            for b in bytes_list:
                int(b, 16)
        except ValueError:
            return

        # Apply basic ID filter
        filter_text = self.filter_entry.get().upper()
        if filter_text and filter_text not in can_id.upper():
            return

        # Apply advanced filters
        if hasattr(self, 'filter_settings'):
            filters = self.filter_settings

            # DLC range filter
            if not (filters['min_dlc'] <= dlc_int <= filters['max_dlc']):
                return

            # Whitelist filter
            if filters['id_whitelist'] and can_id.upper() not in filters['id_whitelist']:
                return

            # Blacklist filter
            if can_id.upper() in filters['id_blacklist']:
                return

            # Hide all-zero data
            if filters['hide_zero_data'] and all(b == "00" for b in bytes_list):
                return

            # Hide periodic (if message exists and hasn't changed)
            if filters['hide_periodic'] and can_id in self.can_rows:
                if self.can_rows[can_id]['last_data'] == bytes_list:
                    return

            # Show only changed (only show if message changed in last 2 seconds)
            if filters['show_only_changed'] and can_id in self.can_rows:
                if not hasattr(self.can_rows[can_id], 'last_change_time'):
                    return
                if (datetime.now() - self.can_rows[can_id].get('last_change_time', datetime.now())).total_seconds() > 2:
                    return

        data_str = " ".join(bytes_list)
        current_mode = self.view_mode.get()

        dev_name = self.id_labels.get(can_id, "Unknown")
        mapping = self.function_labels.get(can_id, {})
        det_func = mapping.get("mappings", {}).get(data_str, "---")

        # Calculate relative timestamp (NEW)
        if timestamp and self.session_start_time:
            relative_time = (timestamp - self.session_start_time).total_seconds()
        else:
            relative_time = 0.0

        if current_mode == "Stream":
            self._update_stream_view(can_id, rtr, ide, dlc, bytes_list, dev_name, det_func)
        else:
            self._update_grouped_view(can_id, rtr, ide, dlc, bytes_list, dev_name, det_func, data_str, relative_time)

    def _update_stream_view(self, can_id, rtr, ide, dlc, bytes_list, dev_name, det_func):
        """Update stream view"""
        if self.sort_newest_first:
            # Insert at top, shift everything down
            if len(self.all_msgs_widgets) >= MAX_ALL_ROWS:
                # Remove last (oldest)
                oldest = self.all_msgs_widgets.pop()
                for w in oldest:
                    try:
                        w.destroy()
                    except:
                        pass

            # Shift all rows down
            for row_widgets in self.all_msgs_widgets:
                for widget in row_widgets:
                    try:
                        current_row = widget.grid_info()['row']
                        widget.grid(row=current_row + 1)
                    except:
                        pass

            row = 1  # New message at top
            self.row_counter_all += 1
        else:
            # Default: add at bottom
            if len(self.all_msgs_widgets) >= MAX_ALL_ROWS:
                oldest = self.all_msgs_widgets.pop(0)
                for w in oldest:
                    try:
                        w.destroy()
                    except:
                        pass

            row = self.row_counter_all
            self.row_counter_all += 1

        bg = Colors.BG_MEDIUM if row % 2 == 0 else Colors.BG_DARK

        widgets = []

        def add_lbl(txt, col, color=Colors.TEXT_PRIMARY, width=50):
            # Apply consistent widths
            if col == 0:  # ID
                width = 60
            elif col == 1:  # Device
                width = 100
            elif col == 2:  # Function
                width = 120
            elif col in [3, 4, 5]:  # RTR, IDE, DLC
                width = 35
            elif col >= 6 and col <= 13:  # D0-D7
                width = 45
            elif col == 14:  # Time
                width = 80

            l = ctk.CTkLabel(
                self.scroll_all,
                text=txt,
                fg_color=bg,
                text_color=color,
                width=width,
                anchor="w",
                font=ctk.CTkFont(size=11)
            )
            l.grid(row=row, column=col, padx=4, pady=1, sticky="ew")
            widgets.append(l)

        add_lbl(can_id, 0, Colors.PRIMARY)
        add_lbl(dev_name, 1, Colors.SUCCESS if dev_name != "Unknown" else Colors.TEXT_MUTED)
        add_lbl(det_func, 2, Colors.WARNING if det_func != "---" else Colors.TEXT_MUTED)
        add_lbl(rtr, 3, Colors.TEXT_SECONDARY)
        add_lbl(ide, 4, Colors.TEXT_SECONDARY)
        add_lbl(dlc, 5, Colors.TEXT_SECONDARY)

        for j in range(8):
            val = bytes_list[j]
            color = Colors.DANGER if val != "00" else Colors.TEXT_MUTED
            add_lbl(val, 6 + j, color)

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        add_lbl(timestamp, 14, Colors.TEXT_MUTED)

        # ADD SAVE BUTTON
        data_str = " ".join(bytes_list)
        btn = ctk.CTkButton(
            self.scroll_all,
            text="+",
            width=40,  # CHANGED
            height=24,
            command=lambda: self._save_function_stream(can_id, data_str),
            fg_color=Colors.SUCCESS,
            hover_color="#059669",
            corner_radius=6,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        btn.grid(row=row, column=15, padx=4, pady=1)
        widgets.append(btn)

        if self.sort_newest_first:
            # Insert at beginning for newest first
            self.all_msgs_widgets.insert(0, widgets)
        else:
            # Append at end for oldest first
            self.all_msgs_widgets.append(widgets)

    def _save_function_stream(self, can_id: str, data_str: str):
        """Save function for CAN ID from stream view"""
        dev_label = self.id_labels.get(can_id, "Unknown")

        dialog = ctk.CTkInputDialog(
            text=f"ID: {can_id}\nLabel: {dev_label}\nFunction for: {data_str}",
            title="Function Database"
        )
        val = dialog.get_input()

        if val:
            if can_id not in self.function_labels:
                self.function_labels[can_id] = {"device": dev_label, "mappings": {}}
            self.function_labels[can_id]["device"] = dev_label
            self.function_labels[can_id]["mappings"][data_str] = val
            self._save_db(DB_FUNCTIONS, self.function_labels)
            self._update_tx_list()
            self._show_status(f"✓ Function saved for ID {can_id}", 3000, Colors.SUCCESS)

    def _update_grouped_view(self, can_id, rtr, ide, dlc, bytes_list, dev_name, det_func, data_str, relative_time=0.0):
        """Update grouped view"""
        if can_id not in self.can_rows:
            # NEW ROW - insert at correct position based on sort order
            if self.sort_newest_first:
                # Insert at top (row 1)
                row = 1
                # Shift all existing rows down
                for existing_id, existing_row in self.can_rows.items():
                    for widget in existing_row['widgets']:
                        try:
                            current_row = widget.grid_info()['row']
                            widget.grid(row=current_row + 1)
                        except:
                            pass
                self.row_counter_grouped += 1
            else:
                # Insert at bottom (default)
                row = self.row_counter_grouped
                self.row_counter_grouped += 1

            # Alternating background color - ALWAYS use BG_MEDIUM for highlight
            bg = Colors.BG_MEDIUM

            # NEW: Timestamp label (column 0)
            time_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=f"{relative_time:.3f}",
                text_color=Colors.TEXT_MUTED,
                width=70,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            time_l.grid(row=row, column=0, padx=4, pady=4, sticky="ew")

            id_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=can_id,
                text_color=Colors.PRIMARY,
                cursor="hand2",
                width=60,
                fg_color=bg,
                font=ctk.CTkFont(size=11, weight="bold")
            )
            id_l.grid(row=row, column=1, padx=4, pady=4, sticky="ew")
            id_l.bind("<Button-1>", lambda e, cid=can_id: self._open_id_edit(cid))

            dev_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=dev_name,
                text_color=Colors.SUCCESS if dev_name != "Unknown" else Colors.TEXT_MUTED,
                width=100,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            dev_l.grid(row=row, column=2, padx=4, pady=4, sticky="ew")

            func_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=det_func,
                text_color=Colors.WARNING if det_func != "---" else Colors.TEXT_MUTED,
                width=120,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            func_l.grid(row=row, column=3, padx=4, pady=4, sticky="ew")

            rtr_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=rtr,
                text_color=Colors.TEXT_SECONDARY,
                width=35,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            rtr_l.grid(row=row, column=4, padx=4, pady=4, sticky="ew")

            ide_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=ide,
                text_color=Colors.TEXT_SECONDARY,
                width=35,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            ide_l.grid(row=row, column=5, padx=4, pady=4, sticky="ew")

            dlc_l = ctk.CTkLabel(
                self.scroll_grouped,
                text=dlc,
                text_color=Colors.TEXT_SECONDARY,
                width=35,
                fg_color=bg,
                font=ctk.CTkFont(size=11)
            )
            dlc_l.grid(row=row, column=6, padx=4, pady=4, sticky="ew")

            b_labels = []
            for j in range(8):
                val = bytes_list[j]
                color = Colors.DANGER if val != "00" else Colors.TEXT_MUTED
                l = ctk.CTkLabel(
                    self.scroll_grouped,
                    text=val,
                    text_color=color,
                    width=45,
                    fg_color=bg,
                    font=ctk.CTkFont(size=11)
                )
                l.grid(row=row, column=7 + j, padx=4, pady=4, sticky="ew")
                b_labels.append(l)

            btn = ctk.CTkButton(
                self.scroll_grouped,
                text="+",
                width=40,
                height=28,
                command=lambda cid=can_id: self._save_function(cid),
                fg_color=Colors.SUCCESS,
                hover_color="#059669",
                corner_radius=6,
                font=ctk.CTkFont(size=14, weight="bold")
            )
            btn.grid(row=row, column=15, padx=4, pady=4)

            widgets = [time_l, id_l, dev_l, func_l, rtr_l, ide_l, dlc_l] + b_labels
            self.can_rows[can_id] = {
                'time_lbl': time_l,  # NEW
                'dev_lbl': dev_l,
                'func_lbl': func_l,
                'bytes': b_labels,
                'last_data': bytes_list.copy(),
                'widgets': widgets + [btn],
                'bg': bg,
                'timestamp': relative_time  # NEW
            }

            # Highlight animation - fade background to transparent (dark)
            def fade():
                try:
                    for w in widgets:
                        if w.winfo_exists():
                            w.configure(fg_color=Colors.BG_DARK)
                except:
                    pass

            self.after(2000, fade)

        else:
            # Update existing row
            r = self.can_rows[can_id]

            # Update timestamp (NEW)
            r['time_lbl'].configure(text=f"{relative_time:.3f}")
            r['timestamp'] = relative_time

            r['func_lbl'].configure(
                text=det_func,
                text_color=Colors.WARNING if det_func != "---" else Colors.TEXT_MUTED
            )

            # Update bytes with MORE VISIBLE change animation
            for i in range(8):
                if i < len(bytes_list):
                    current_val = bytes_list[i]

                    if i < len(r['last_data']) and current_val != r['last_data'][i]:
                        lbl = r['bytes'][i]

                        # BRIGHT highlight with red background
                        lbl.configure(
                            text=current_val,
                            text_color="#FFFFFF",
                            font=ctk.CTkFont(weight="bold", size=12),
                            fg_color="#DC2626"
                        )

                        # Create closure with current values
                        def make_reset(label, value):
                            def reset():
                                try:
                                    if label.winfo_exists():
                                        byte_color = Colors.DANGER if value != "00" else Colors.TEXT_MUTED
                                        label.configure(
                                            text=value,
                                            text_color=byte_color,
                                            font=ctk.CTkFont(weight="normal", size=11),
                                            fg_color="transparent"
                                        )
                                except:
                                    pass

                            return reset

                        self.after(350, make_reset(lbl, current_val))

            # Update last_data after all changes
            r['last_data'] = bytes_list[:]

    def handle_send_click(self):
        """Handle send button click"""
        if self.is_sending_active:
            self.is_sending_active = False
            self.btn_send.configure(text="SEND COMMAND", fg_color=Colors.SECONDARY)
            return

        if not self.ser or not self.ser.is_open:
            messagebox.showwarning("Error", "No connection!")
            return

        selection = self.tx_combo.get()
        if not selection or selection == "No functions saved":
            return

        try:
            count = int(self.entry_repeat.get())
            interval_ms = int(self.entry_interval.get())
        except:
            messagebox.showerror("Error", "Invalid count or interval!")
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
            self.btn_send.configure(text="⏹ STOP", fg_color=Colors.DANGER)
            threading.Thread(
                target=self._sending_loop,
                args=(target_id, data_to_send, count, interval_ms),
                daemon=True
            ).start()

    def _sending_loop(self, target_id: str, data_str: str, count: int, interval_ms: int):
        """Transmission loop"""
        command = f"SEND:{target_id}|{data_str}\n"
        encoded = command.encode('utf-8')

        for i in range(count):
            if not self.is_sending_active or not self.is_sniffing:
                break
            try:
                self.ser.write(encoded)
            except:
                self.is_sending_active = False
                break
            time.sleep(interval_ms / 1000.0)

        self.is_sending_active = False
        self.after(0, lambda: self.btn_send.configure(text="SEND COMMAND", fg_color=Colors.SECONDARY))

    def win_manage_ids(self):
        """ID management window"""
        win = ctk.CTkToplevel(self)
        win.title("Manage IDs")
        win.geometry("600x500")
        win.attributes("-topmost", True)
        win.configure(fg_color=Colors.BG_DARK)  # Dark background

        # Style for treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=Colors.BG_MEDIUM,
                        foreground=Colors.TEXT_PRIMARY,
                        fieldbackground=Colors.BG_MEDIUM,
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background=Colors.BG_LIGHT,
                        foreground=Colors.TEXT_PRIMARY,
                        borderwidth=0)
        style.map('Treeview', background=[('selected', Colors.PRIMARY)])

        tree = ttk.Treeview(win, columns=("id", "name"), show='headings')
        tree.heading("id", text="ID (Hex)")
        tree.heading("name", text="Device Name")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def reload():
            for i in tree.get_children():
                tree.delete(i)
            for k in sorted(self.id_labels.keys()):
                tree.insert('', tk.END, values=(k, self.id_labels[k]))

        def delete():
            sel = tree.selection()
            if sel:
                cid = str(tree.item(sel[0])['values'][0])
                if messagebox.askyesno("Delete", f"Delete description for ID {cid}?"):
                    del self.id_labels[cid]
                    self._save_db(DB_IDS, self.id_labels)
                    if cid in self.can_rows:
                        self.can_rows[cid]['dev_lbl'].configure(text="Unknown", text_color=Colors.TEXT_MUTED)
                    reload()
                    self._update_tx_list()

        def edit():
            sel = tree.selection()
            if sel:
                cid = str(tree.item(sel[0])['values'][0])
                old_name = self.id_labels.get(cid, "")
                dialog = ctk.CTkInputDialog(
                    text=f"Edit name for ID {cid}:\n(Current: {old_name})",
                    title="Edit ID"
                )
                new_name = dialog.get_input()
                if new_name:
                    self.id_labels[cid] = new_name
                    self._save_db(DB_IDS, self.id_labels)
                    if cid in self.can_rows:
                        self.can_rows[cid]['dev_lbl'].configure(text=new_name, text_color=Colors.SUCCESS)
                    reload()
                    self._update_tx_list()
            else:
                messagebox.showinfo("Info", "Select a row to edit.")

        btn_frame = ctk.CTkFrame(win, fg_color=Colors.BG_DARK)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(btn_frame, text="Delete", fg_color=Colors.DANGER, width=100, command=delete).pack(side="left",
                                                                                                        padx=5)
        ctk.CTkButton(btn_frame, text="Edit", fg_color=Colors.WARNING, width=100, command=edit).pack(side="left",
                                                                                                     padx=5)

        reload()

    def win_manage_funcs(self):
        """Function management window"""
        win = ctk.CTkToplevel(self)
        win.title("Manage Functions")
        win.geometry("900x500")
        win.attributes("-topmost", True)
        win.configure(fg_color=Colors.BG_DARK)  # Dark background

        # Style for treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=Colors.BG_MEDIUM,
                        foreground=Colors.TEXT_PRIMARY,
                        fieldbackground=Colors.BG_MEDIUM,
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background=Colors.BG_LIGHT,
                        foreground=Colors.TEXT_PRIMARY,
                        borderwidth=0)
        style.map('Treeview', background=[('selected', Colors.PRIMARY)])

        tree = ttk.Treeview(win, columns=("id", "dev", "data", "func"), show='headings')
        tree.heading("id", text="ID")
        tree.heading("dev", text="Device")
        tree.heading("data", text="Data Pattern")
        tree.heading("func", text="Function Description")
        tree.column("id", width=60, anchor="center")
        tree.column("dev", width=150, anchor="w")
        tree.column("data", width=250, anchor="center")
        tree.column("func", width=300, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def reload():
            for i in tree.get_children():
                tree.delete(i)
            for cid in sorted(self.function_labels.keys()):
                obj = self.function_labels[cid]
                for d, f in obj.get("mappings", {}).items():
                    tree.insert('', tk.END, values=(cid, obj.get("device", "---"), d, f))

        def delete():
            sel = tree.selection()
            if sel:
                v = tree.item(sel[0])['values']
                cid, d_str = str(v[0]), str(v[2])
                if messagebox.askyesno("Delete", "Delete this function?"):
                    del self.function_labels[cid]["mappings"][d_str]
                    if not self.function_labels[cid]["mappings"]:
                        del self.function_labels[cid]
                    self._save_db(DB_FUNCTIONS, self.function_labels)
                    reload()
                    self._update_tx_list()

        def edit():
            sel = tree.selection()
            if sel:
                v = tree.item(sel[0])['values']
                cid = str(v[0])
                d_str = str(v[2])
                old_func = str(v[3])
                dialog = ctk.CTkInputDialog(
                    text=f"Edit function description for ID {cid}:\n[{d_str}]",
                    title="Edit Function"
                )
                new_func = dialog.get_input()
                if new_func:
                    self.function_labels[cid]["mappings"][d_str] = new_func
                    self._save_db(DB_FUNCTIONS, self.function_labels)
                    if cid in self.can_rows:
                        current_data = " ".join(self.can_rows[cid]['last_data'])
                        if current_data == d_str:
                            self.can_rows[cid]['func_lbl'].configure(text=new_func, text_color=Colors.WARNING)
                    reload()
                    self._update_tx_list()
            else:
                messagebox.showinfo("Info", "Select a row to edit.")

        btn_frame = ctk.CTkFrame(win, fg_color=Colors.BG_DARK)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(btn_frame, text="Delete", fg_color=Colors.DANGER, width=100, command=delete).pack(side="left",
                                                                                                        padx=5)
        ctk.CTkButton(btn_frame, text="Edit", fg_color=Colors.WARNING, width=100, command=edit).pack(side="left",
                                                                                                     padx=5)

        reload()

    def _open_id_edit(self, can_id: str):
        """Open ID edit dialog"""
        dialog = ctk.CTkInputDialog(text=f"Label for {can_id}:", title="ID Database")
        value = dialog.get_input()
        if value:
            self.id_labels[can_id] = value
            self._save_db(DB_IDS, self.id_labels)
            if can_id in self.can_rows:
                self.can_rows[can_id]['dev_lbl'].configure(text=value, text_color=Colors.SUCCESS)
            self._update_tx_list()

    def _save_function(self, can_id: str):
        """Save function for CAN ID"""
        if can_id in self.can_rows:
            data_str = " ".join(self.can_rows[can_id]['last_data'])
        else:
            return

        dev_label = self.id_labels.get(can_id, "Unknown")
        dialog = ctk.CTkInputDialog(
            text=f"ID: {can_id}\nLabel: {dev_label}\nFunction for: {data_str}",
            title="Function Database"
        )
        val = dialog.get_input()

        if val:
            if can_id not in self.function_labels:
                self.function_labels[can_id] = {"device": dev_label, "mappings": {}}
            self.function_labels[can_id]["device"] = dev_label
            self.function_labels[can_id]["mappings"][data_str] = val
            self._save_db(DB_FUNCTIONS, self.function_labels)
            if can_id in self.can_rows:
                self.can_rows[can_id]['func_lbl'].configure(text=val, text_color=Colors.WARNING)
            self._update_tx_list()

    def _clear_monitor(self):
        """Clear monitor display with modern dialog"""
        # Create custom dialog
        dialog = ctk.CTkToplevel(self)
        dialog.title("Clear Monitor")
        dialog.geometry("450x250")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (225)
        y = (dialog.winfo_screenheight() // 2) - (125)
        dialog.geometry(f"450x250+{x}+{y}")

        dialog.configure(fg_color=Colors.BG_DARK)

        response = {"value": None}

        main_frame = ctk.CTkFrame(dialog, fg_color=Colors.BG_DARK)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="Clear display and reset statistics?",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(pady=(10, 20))

        ctk.CTkLabel(
            main_frame,
            text="• Yes = Clear display + reset stats\n• No = Clear display only\n• Cancel = Do nothing",
            font=ctk.CTkFont(size=12),
            text_color=Colors.TEXT_SECONDARY,
            justify="left"
        ).pack(pady=10)

        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(side="bottom", pady=(20, 10))

        def on_yes():
            response["value"] = True
            dialog.destroy()

        def on_no():
            response["value"] = False
            dialog.destroy()

        def on_cancel():
            response["value"] = None
            dialog.destroy()

        ctk.CTkButton(
            btn_frame,
            text="Yes",
            command=on_yes,
            fg_color=Colors.SUCCESS,
            hover_color="#059669",
            width=120,
            height=36
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="No",
            command=on_no,
            fg_color=Colors.WARNING,
            hover_color="#D97706",
            width=120,
            height=36
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Cancel",
            command=on_cancel,
            fg_color=Colors.BG_LIGHT,
            hover_color=Colors.BG_MEDIUM,
            width=120,
            height=36
        ).pack(side="left", padx=5)

        self.wait_window(dialog)

        if response["value"] is None:
            return

        # Clear grouped view
        for r in self.can_rows.values():
            for w in r['widgets']:
                try:
                    w.destroy()
                except:
                    pass
        self.can_rows.clear()
        self.row_counter_grouped = 1

        # Clear stream view
        for row_widgets in self.all_msgs_widgets:
            for w in row_widgets:
                try:
                    w.destroy()
                except:
                    pass
        self.all_msgs_widgets.clear()
        self.row_counter_all = 1

        # Reset stats if Yes - NO MORE MESSAGEBOX!
        if response["value"]:
            self.session_log.clear()
            self.stats = {
                'total_frames': 0,
                'frames_per_id': {},
                'start_time': datetime.now() if self.is_sniffing else None
            }
            self._show_status("✓ Display and statistics cleared!", 4000, Colors.SUCCESS)
        else:
            self._show_status("✓ Display cleared (statistics preserved)", 4000, Colors.INFO)

        self.session_start_time = datetime.now() if self.is_sniffing else None  # Add after stats reset

    def _show_toast(self, message: str, color: str):
        """Show a temporary toast notification"""
        toast = ctk.CTkFrame(
            self,
            fg_color=color,
            corner_radius=8
        )
        toast.place(relx=0.5, rely=0.95, anchor="center")

        ctk.CTkLabel(
            toast,
            text=message,
            font=ctk.CTkFont(size=12),
            text_color="white"
        ).pack(padx=20, pady=10)

        def fade_out():
            try:
                toast.destroy()
            except:
                pass

        self.after(2000, fade_out)

    def export_session_log(self):
        """Export captured CAN traffic to CSV"""
        if not self.session_log:
            self._show_status("⚠ No data to export!", 3000, Colors.WARNING)
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"can_log_{timestamp}.csv"

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'id', 'rtr', 'ide', 'dlc', 'data'])
                writer.writeheader()
                writer.writerows(self.session_log)

            self._show_status(f"✓ Saved {len(self.session_log)} frames to {filename}", 5000, Colors.SUCCESS)
        except Exception as e:
            self._show_status(f"✗ Failed to save log: {str(e)}", 5000, Colors.DANGER)

    def show_statistics(self):
        """Display session statistics"""
        win = ctk.CTkToplevel(self)
        win.title("Session Statistics")
        win.geometry("600x500")
        win.attributes("-topmost", True)

        # Calculate stats
        total = self.stats['total_frames']
        unique_ids = len(self.stats['frames_per_id'])

        if self.stats['start_time']:
            elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
            fps = total / elapsed if elapsed > 0 else 0
        else:
            elapsed = 0
            fps = 0

        # Overall stats
        info_frame = ctk.CTkFrame(win, fg_color=Colors.BG_MEDIUM)
        info_frame.pack(fill="x", padx=15, pady=15)

        ctk.CTkLabel(
            info_frame,
            text=f"Total Frames: {total}",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=8)
        ctk.CTkLabel(info_frame, text=f"Unique IDs: {unique_ids}").pack(pady=4)
        ctk.CTkLabel(info_frame, text=f"Elapsed Time: {elapsed:.1f}s").pack(pady=4)
        ctk.CTkLabel(info_frame, text=f"Average Rate: {fps:.1f} fps").pack(pady=4)

        # Top IDs
        ctk.CTkLabel(
            win,
            text="Top Active IDs:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(pady=(15, 5))

        tree_frame = ctk.CTkFrame(win)
        tree_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        tree = ttk.Treeview(tree_frame, columns=("id", "count", "percent"), show='headings', height=15)
        tree.heading("id", text="CAN ID")
        tree.heading("count", text="Frame Count")
        tree.heading("percent", text="Percentage")
        tree.column("id", width=150, anchor="center")
        tree.column("count", width=150, anchor="center")
        tree.column("percent", width=150, anchor="center")
        tree.pack(fill="both", expand=True)

        sorted_ids = sorted(self.stats['frames_per_id'].items(), key=lambda x: x[1], reverse=True)

        for can_id, count in sorted_ids[:20]:
            percent = (count / total * 100) if total > 0 else 0
            device = self.id_labels.get(can_id, "Unknown")
            tree.insert('', tk.END, values=(f"{can_id} ({device})", count, f"{percent:.1f}%"))
# ==================== MANUAL FRAME TRANSMISSION ====================

    def open_manual_transmit(self):
        """Open manual frame transmission window"""
        win = ctk.CTkToplevel(self)
        win.title("Manual Frame Transmission")
        win.geometry("700x550")
        win.attributes("-topmost", True)
        win.configure(fg_color=Colors.BG_DARK)

        main_frame = ctk.CTkFrame(win, fg_color=Colors.BG_DARK)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="Manual CAN Frame Transmission",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color=Colors.TEXT_PRIMARY).pack(pady=(0, 20))

        input_frame = ctk.CTkFrame(main_frame, fg_color=Colors.BG_MEDIUM, corner_radius=8)
        input_frame.pack(fill="x", pady=(0, 15))

        # Row 1: ID, RTR, IDE, DLC
        row1 = ctk.CTkFrame(input_frame, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(row1, text="ID (Hex):", width=70).pack(side="left", padx=(0, 5))
        id_entry = ctk.CTkEntry(row1, width=80, fg_color=Colors.BG_LIGHT, placeholder_text="e.g. 7DF")
        id_entry.pack(side="left", padx=(0, 20))

        ctk.CTkLabel(row1, text="RTR:").pack(side="left", padx=(0, 5))
        rtr_var = ctk.StringVar(value="0")
        ctk.CTkComboBox(row1, values=["0", "1"], width=60, variable=rtr_var, fg_color=Colors.BG_LIGHT).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(row1, text="IDE:").pack(side="left", padx=(0, 5))
        ide_var = ctk.StringVar(value="0")
        ctk.CTkComboBox(row1, values=["0", "1"], width=60, variable=ide_var, fg_color=Colors.BG_LIGHT).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(row1, text="DLC:").pack(side="left", padx=(0, 5))
        dlc_var = ctk.StringVar(value="8")
        ctk.CTkComboBox(row1, values=["0", "1", "2", "3", "4", "5", "6", "7", "8"], width=60,
                        variable=dlc_var, fg_color=Colors.BG_LIGHT).pack(side="left")

        # Row 2: Data bytes
        row2 = ctk.CTkFrame(input_frame, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(row2, text="Data (Hex):", width=70).pack(side="left", padx=(0, 5))

        byte_entries = []
        for i in range(8):
            ctk.CTkLabel(row2, text=f"D{i}:", font=ctk.CTkFont(size=10)).pack(side="left", padx=(5, 2))
            entry = ctk.CTkEntry(row2, width=40, fg_color=Colors.BG_LIGHT, placeholder_text="00")
            entry.pack(side="left", padx=(0, 5))
            byte_entries.append(entry)

        # Row 3: Quick data input
        row3 = ctk.CTkFrame(input_frame, fg_color="transparent")
        row3.pack(fill="x", padx=15, pady=(0, 15))

        ctk.CTkLabel(row3, text="Or paste data:", width=85).pack(side="left", padx=(0, 5))
        quick_data_entry = ctk.CTkEntry(row3, width=300, fg_color=Colors.BG_LIGHT,
                                        placeholder_text="e.g. 1B 2C 3D 4E 5F 00 00 00")
        quick_data_entry.pack(side="left", padx=(0, 10))

        def parse_quick_data():
            data = quick_data_entry.get().strip().upper().replace(",", " ").replace("-", " ").replace(":", " ")
            parts = data.split()
            for i, entry in enumerate(byte_entries):
                entry.delete(0, "end")
                if i < len(parts):
                    try:
                        int(parts[i], 16)
                        entry.insert(0, parts[i].zfill(2))
                    except ValueError:
                        entry.insert(0, "00")
                else:
                    entry.insert(0, "00")

        ctk.CTkButton(row3, text="Parse", width=60, command=parse_quick_data, fg_color=Colors.INFO).pack(side="left")

        # Transmission list
        ctk.CTkLabel(main_frame, text="Transmission Queue:", font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=Colors.TEXT_SECONDARY).pack(anchor="w", pady=(10, 5))

        list_frame = ctk.CTkFrame(main_frame, fg_color=Colors.BG_MEDIUM)
        list_frame.pack(fill="both", expand=True, pady=(0, 10))

        style = ttk.Style()
        style.configure("Manual.Treeview", background=Colors.BG_MEDIUM, foreground=Colors.TEXT_PRIMARY,
                        fieldbackground=Colors.BG_MEDIUM)
        style.configure("Manual.Treeview.Heading", background=Colors.BG_LIGHT, foreground=Colors.TEXT_PRIMARY)

        tree = ttk.Treeview(list_frame, columns=("id", "rtr", "ide", "dlc", "data"), show='headings',
                            style="Manual.Treeview", height=8)
        tree.heading("id", text="ID")
        tree.heading("rtr", text="RTR")
        tree.heading("ide", text="IDE")
        tree.heading("dlc", text="DLC")
        tree.heading("data", text="Data")
        tree.column("id", width=80, anchor="center")
        tree.column("rtr", width=50, anchor="center")
        tree.column("ide", width=50, anchor="center")
        tree.column("dlc", width=50, anchor="center")
        tree.column("data", width=300, anchor="center")
        tree.pack(fill="both", expand=True, padx=5, pady=5)

        manual_frames = []

        def add_frame():
            can_id = id_entry.get().strip().upper()
            if not can_id:
                self._show_status("⚠ ID is required!", 3000, Colors.WARNING)
                return
            try:
                int(can_id, 16)
            except ValueError:
                self._show_status("⚠ Invalid hex ID!", 3000, Colors.WARNING)
                return

            data_bytes = []
            dlc = int(dlc_var.get())
            for i in range(dlc):
                val = byte_entries[i].get().strip().upper() or "00"
                try:
                    int(val, 16)
                    data_bytes.append(val.zfill(2))
                except ValueError:
                    self._show_status(f"⚠ Invalid hex in D{i}!", 3000, Colors.WARNING)
                    return

            data_str = " ".join(data_bytes)
            frame = {'id': can_id, 'rtr': rtr_var.get(), 'ide': ide_var.get(), 'dlc': str(dlc), 'data': data_str}
            manual_frames.append(frame)
            tree.insert('', 'end', values=(can_id, rtr_var.get(), ide_var.get(), dlc, data_str))

            id_entry.delete(0, "end")
            for entry in byte_entries:
                entry.delete(0, "end")
            quick_data_entry.delete(0, "end")
            self._show_status(f"✓ Frame added: {can_id}", 2000, Colors.SUCCESS)

        def remove_selected():
            sel = tree.selection()
            if sel:
                idx = tree.index(sel[0])
                tree.delete(sel[0])
                if idx < len(manual_frames):
                    manual_frames.pop(idx)

        def clear_all():
            for item in tree.get_children():
                tree.delete(item)
            manual_frames.clear()

        def send_all():
            if not self.ser or not self.ser.is_open:
                self._show_status("⚠ Not connected!", 3000, Colors.WARNING)
                return
            if not manual_frames:
                self._show_status("⚠ No frames to send!", 3000, Colors.WARNING)
                return
            try:
                delay = int(delay_entry.get())
            except ValueError:
                delay = 10

            def send_thread():
                for frame in manual_frames:
                    if not self.is_sniffing:
                        break
                    command = f"SEND:{frame['id']}|{frame['data']}\n"
                    try:
                        self.ser.write(command.encode('utf-8'))
                    except Exception as e:
                        self.after(0, lambda: self._show_status(f"✗ Send error: {e}", 3000, Colors.DANGER))
                        return
                    time.sleep(delay / 1000.0)
                self.after(0, lambda: self._show_status(f"✓ Sent {len(manual_frames)} frames", 3000, Colors.SUCCESS))

            threading.Thread(target=send_thread, daemon=True).start()

        def send_once_selected():
            sel = tree.selection()
            if not sel:
                self._show_status("⚠ Select a frame!", 3000, Colors.WARNING)
                return
            if not self.ser or not self.ser.is_open:
                self._show_status("⚠ Not connected!", 3000, Colors.WARNING)
                return
            idx = tree.index(sel[0])
            if idx < len(manual_frames):
                frame = manual_frames[idx]
                command = f"SEND:{frame['id']}|{frame['data']}\n"
                try:
                    self.ser.write(command.encode('utf-8'))
                    self._show_status(f"✓ Sent: {frame['id']}", 2000, Colors.SUCCESS)
                except Exception as e:
                    self._show_status(f"✗ Send error: {e}", 3000, Colors.DANGER)

        # Button frame
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x")

        ctk.CTkButton(btn_frame, text="Add Frame", command=add_frame, fg_color=Colors.SUCCESS, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Remove", command=remove_selected, fg_color=Colors.DANGER, width=80).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Clear All", command=clear_all, fg_color=Colors.BG_LIGHT, width=80).pack(side="left", padx=5)

        ctk.CTkFrame(btn_frame, fg_color="transparent", width=50).pack(side="left", padx=10)

        ctk.CTkLabel(btn_frame, text="Delay (ms):").pack(side="left", padx=(0, 5))
        delay_entry = ctk.CTkEntry(btn_frame, width=60, fg_color=Colors.BG_LIGHT)
        delay_entry.insert(0, "10")
        delay_entry.pack(side="left", padx=(0, 10))

        ctk.CTkButton(btn_frame, text="Send Selected", command=send_once_selected, fg_color=Colors.INFO, width=110).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Send All", command=send_all, fg_color=Colors.PRIMARY, width=100).pack(side="left", padx=5)

    # ==================== SESSION LOAD/PLAYBACK ====================

    def load_session_file(self):
        """Load a previously exported CSV session file"""
        filepath = filedialog.askopenfilename(title="Load Session File",
                                              filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not filepath:
            return

        try:
            loaded_frames = []
            with open(filepath, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    loaded_frames.append({
                        'timestamp': row.get('timestamp', '00:00:00.000'),
                        'id': row.get('id', '000').upper(),
                        'rtr': row.get('rtr', '0'),
                        'ide': row.get('ide', '0'),
                        'dlc': row.get('dlc', '8'),
                        'data': row.get('data', '00 00 00 00 00 00 00 00')
                    })

            if not loaded_frames:
                self._show_status("⚠ No frames found in file!", 3000, Colors.WARNING)
                return

            self.loaded_session = loaded_frames
            self._show_status(f"✓ Loaded {len(loaded_frames)} frames from session", 4000, Colors.SUCCESS)

            if messagebox.askyesno("Session Loaded", f"Loaded {len(loaded_frames)} frames.\n\nDisplay them in the monitor now?"):
                self._display_loaded_session()

        except Exception as e:
            self._show_status(f"✗ Failed to load: {e}", 5000, Colors.DANGER)
            messagebox.showerror("Load Error", f"Failed to load session file:\n{str(e)}")

    def _display_loaded_session(self):
        """Display loaded session frames in the monitor"""
        if not self.loaded_session:
            return
        self._clear_monitor_silent()
        for frame in self.loaded_session:
            data_list = frame['data'].split()
            while len(data_list) < 8:
                data_list.append("00")
            self.update_monitor(frame['id'], frame['rtr'], frame['ide'], frame['dlc'], data_list[:8])

    def _clear_monitor_silent(self):
        """Clear monitor without confirmation dialog"""
        for r in self.can_rows.values():
            for w in r['widgets']:
                try:
                    w.destroy()
                except:
                    pass
        self.can_rows.clear()
        self.row_counter_grouped = 1

        for row_widgets in self.all_msgs_widgets:
            for w in row_widgets:
                try:
                    w.destroy()
                except:
                    pass
        self.all_msgs_widgets.clear()
        self.row_counter_all = 1

    def open_playback_dialog(self):
        """Open playback configuration dialog"""
        if not self.loaded_session:
            self.load_session_file()
            if not self.loaded_session:
                return

        win = ctk.CTkToplevel(self)
        win.title("Session Playback")
        win.geometry("500x500")
        win.attributes("-topmost", True)
        win.configure(fg_color=Colors.BG_DARK)

        main_frame = ctk.CTkFrame(win, fg_color=Colors.BG_DARK)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="Session Playback", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=Colors.TEXT_PRIMARY).pack(pady=(0, 20))

        info_frame = ctk.CTkFrame(main_frame, fg_color=Colors.BG_MEDIUM, corner_radius=8)
        info_frame.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(info_frame, text=f"Loaded Session: {len(self.loaded_session)} frames",
                     font=ctk.CTkFont(size=13), text_color=Colors.SUCCESS).pack(pady=15)

        options_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        options_frame.pack(fill="x", pady=(0, 20))

        speed_frame = ctk.CTkFrame(options_frame, fg_color=Colors.BG_MEDIUM, corner_radius=8)
        speed_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(speed_frame, text="Playback Speed:", text_color=Colors.TEXT_SECONDARY).pack(side="left", padx=15, pady=15)
        speed_var = ctk.StringVar(value="1x")
        ctk.CTkComboBox(speed_frame, values=["0.25x", "0.5x", "1x", "2x", "4x", "10x", "Max"],
                        variable=speed_var, width=100, fg_color=Colors.BG_LIGHT).pack(side="left", padx=10, pady=15)

        transmit_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(options_frame, text="Also transmit frames to CAN bus (requires connection)",
                        variable=transmit_var, fg_color=Colors.PRIMARY).pack(anchor="w", pady=10)

        loop_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(options_frame, text="Loop playback continuously",
                        variable=loop_var, fg_color=Colors.PRIMARY).pack(anchor="w", pady=5)

        playback_progress = ctk.CTkProgressBar(main_frame, fg_color=Colors.BG_MEDIUM, progress_color=Colors.SUCCESS)
        playback_progress.pack(fill="x", pady=10)
        playback_progress.set(0)

        playback_status = ctk.CTkLabel(main_frame, text="Ready to play", font=ctk.CTkFont(size=12),
                                       text_color=Colors.TEXT_SECONDARY)
        playback_status.pack(pady=5)

        def get_speed_multiplier():
            speeds = {"0.25x": 4.0, "0.5x": 2.0, "1x": 1.0, "2x": 0.5, "4x": 0.25, "10x": 0.1, "Max": 0.0}
            return speeds.get(speed_var.get(), 1.0)

        def start_playback():
            if self.is_playing_back:
                return
            self.is_playing_back = True
            self._clear_monitor_silent()
            speed_mult = get_speed_multiplier()
            do_transmit = transmit_var.get()
            do_loop = loop_var.get()

            def playback_thread():
                while self.is_playing_back:
                    total = len(self.loaded_session)
                    prev_time = None

                    for idx, frame in enumerate(self.loaded_session):
                        if not self.is_playing_back:
                            break

                        delay = 0.01
                        if speed_mult > 0:
                            try:
                                time_str = frame['timestamp']
                                parts = time_str.split(':')
                                if len(parts) == 3:
                                    h, m, rest = parts
                                    s_parts = rest.split('.')
                                    s = float(s_parts[0])
                                    ms = float(s_parts[1]) / 1000 if len(s_parts) > 1 else 0
                                    current_time = int(h) * 3600 + int(m) * 60 + s + ms
                                    if prev_time is not None:
                                        delay = (current_time - prev_time) * speed_mult
                                        delay = max(0, min(delay, 5.0))
                                    prev_time = current_time
                            except:
                                delay = 0.01 * speed_mult

                        progress = (idx + 1) / total
                        self.after(0, lambda p=progress: playback_progress.set(p))
                        self.after(0, lambda i=idx, t=total: playback_status.configure(text=f"Playing: {i + 1}/{t}"))

                        data_list = frame['data'].split()
                        while len(data_list) < 8:
                            data_list.append("00")

                        self.after(0, lambda f=frame, d=data_list: self.update_monitor(
                            f['id'], f['rtr'], f['ide'], f['dlc'], d[:8]))

                        if do_transmit and self.ser and self.ser.is_open:
                            command = f"SEND:{frame['id']}|{frame['data']}\n"
                            try:
                                self.ser.write(command.encode('utf-8'))
                            except:
                                pass

                        if delay > 0:
                            time.sleep(delay)

                    if not do_loop:
                        break

                self.is_playing_back = False
                self.after(0, lambda: playback_status.configure(text="Playback complete"))
                self.after(0, lambda: self._show_status("✓ Playback complete", 3000, Colors.SUCCESS))

            threading.Thread(target=playback_thread, daemon=True).start()

        def stop_playback():
            self.is_playing_back = False
            playback_status.configure(text="Stopped")

        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(pady=20)

        ctk.CTkButton(btn_frame, text="▶ Play", command=start_playback, fg_color=Colors.SUCCESS,
                      hover_color="#059669", width=120, height=40).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="⏹ Stop", command=stop_playback, fg_color=Colors.DANGER,
                      hover_color="#DC2626", width=120, height=40).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Close", command=lambda: [stop_playback(), win.destroy()],
                      fg_color=Colors.BG_LIGHT, width=100, height=40).pack(side="left", padx=10)

if __name__ == "__main__":
    app = ModernCANApp()
    app.mainloop()