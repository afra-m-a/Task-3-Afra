import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import re

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class SegmentedProgressBar(ctk.CTkFrame):
    def __init__(self, master, width=300, height=20, **kwargs):
        super().__init__(master, width=width, height=height, fg_color="transparent", **kwargs)
        self.width = width
        self.height = height
        self.score = 0
        self.canvas = tk.Canvas(self, width=width, height=height, bg="#121214", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.draw_segments()
        self.draw_indicator()

    def draw_segments(self):
        self.canvas.delete("segment")
        w = self.width
        h = self.height
        self.canvas.create_rectangle(0, 0, w*0.33, h, fill="#10B981", outline="", tags="segment")
    
        self.canvas.create_rectangle(w*0.33, 0, w*0.66, h, fill="#F59E0B", outline="", tags="segment")
       
        self.canvas.create_rectangle(w*0.66, 0, w, h, fill="#EF4444", outline="", tags="segment")
        self.canvas.create_rectangle(0, 0, w, h, outline="#3F3F46", width=1, tags="segment")

    def draw_indicator(self):
        self.canvas.delete("indicator")
        x_pos = (self.score / 100.0) * self.width
        x_pos = max(5, min(self.width-5, x_pos))
        size = 8
        points = [x_pos, 0, x_pos+size/2, size/2, x_pos, size, x_pos-size/2, size/2]
        self.canvas.create_polygon(points, fill="#FFFFFF", outline="#A1A1AA", width=1, tags="indicator")

    def set_value(self, score):
        self.score = max(0, min(100, score))
        self.draw_indicator()

class PhishingTriageApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ThreatScope // Malicious Email Analyzer")
        self.geometry("1280x850")
        self.configure(fg_color="#121214")
        self.resizable(True, True)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)  # header
        self.grid_rowconfigure(1, weight=1)  # content

        self.header_frame = ctk.CTkFrame(self, fg_color="#1E1E22", corner_radius=0, height=80)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self.header_frame.grid_propagate(False)

        title_label = ctk.CTkLabel(
            self.header_frame, 
            text="ThreatScope // Malicious Email Analyzer",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="#FFFFFF"
        )
        title_label.pack(side="top", pady=(15, 5))

        subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text="Enterprise Email Verification & Simulation Sandbox",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#A1A1AA"
        )
        subtitle_label.pack()

        self.tabview = ctk.CTkTabview(self, fg_color="#121214", segmented_button_fg_color="#1E1E22",
                                      segmented_button_selected_color="#6366F1", corner_radius=12)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.tabview.add("Live Triage")
        self.tabview.add("Simulation Sandbox")

        self.live_tab = self.tabview.tab("Live Triage")
        self.live_tab.grid_columnconfigure(0, weight=1)
        self.live_tab.grid_rowconfigure(2, weight=1)  

        input_frame = ctk.CTkFrame(self.live_tab, fg_color="#1E1E22", corner_radius=12)
        input_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_frame, text="📧 Payload & Headers", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#D4D4D8").grid(row=0, column=0, sticky="w", padx=15, pady=(10, 5))

        self.payload_text = ctk.CTkTextbox(input_frame, height=180, corner_radius=8, border_width=1,
                                           border_color="#3F3F46", fg_color="#252529", font=ctk.CTkFont(family="Consolas", size=12))
        self.payload_text.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        self.payload_text.insert("0.0", "Paste email headers and body here for analysis...")

        button_row = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_row.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        button_row.grid_columnconfigure(0, weight=1)

        self.analyze_btn = ctk.CTkButton(button_row, text="🔍 Analyze Payload", command=self.analyze_payload,
                                         fg_color="#6366F1", hover_color="#4F46E5", corner_radius=8,
                                         font=ctk.CTkFont(size=14, weight="bold"), height=40, width=200)
        self.analyze_btn.grid(row=0, column=0, sticky="w")

        self.copy_btn = ctk.CTkButton(button_row, text="📋 Copy Log Data", command=self.copy_log_data,
                                      fg_color="transparent", border_width=1, border_color="#6366F1",
                                      text_color="#A1A1AA", hover_color="#2D2D35", corner_radius=8,
                                      font=ctk.CTkFont(size=12), height=36, width=140)
        self.copy_btn.grid(row=0, column=1, sticky="e", padx=(0, 0))

        dashboard_frame = ctk.CTkFrame(self.live_tab, fg_color="transparent")
        dashboard_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
        dashboard_frame.grid_columnconfigure((0,1,2), weight=1, uniform="card")
        dashboard_frame.grid_rowconfigure(0, weight=1)

        self.risk_card = ctk.CTkFrame(dashboard_frame, fg_color="#1E1E22", corner_radius=12)
        self.risk_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=10)

        ctk.CTkLabel(self.risk_card, text="RISK ASSESSMENT", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#F4F4F5").pack(anchor="w", padx=15, pady=(15, 5))
        self.risk_score_label = ctk.CTkLabel(self.risk_card, text="0", font=ctk.CTkFont(size=48, weight="bold"),
                                             text_color="#FFFFFF")
        self.risk_score_label.pack(anchor="w", padx=15, pady=(0, 5))
        ctk.CTkLabel(self.risk_card, text="/ 100", font=ctk.CTkFont(size=16), text_color="#71717A").place(x=85, y=58)
        self.risk_level_label = ctk.CTkLabel(self.risk_card, text="UNKNOWN", font=ctk.CTkFont(size=16, weight="bold"),
                                             text_color="#A1A1AA")
        self.risk_level_label.pack(anchor="w", padx=15, pady=(0, 15))

        self.progress_bar = SegmentedProgressBar(self.risk_card, width=250, height=16)
        self.progress_bar.pack(pady=(10, 20), padx=15, fill="x")

        self.flags_card = ctk.CTkFrame(dashboard_frame, fg_color="#1E1E22", corner_radius=12)
        self.flags_card.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        ctk.CTkLabel(self.flags_card, text="TELEMETRY FLAGS", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#F4F4F5").pack(anchor="w", padx=15, pady=(15, 5))

        self.flags_scroll = ctk.CTkScrollableFrame(self.flags_card, fg_color="transparent", height=200)
        self.flags_scroll.pack(fill="both", expand=True, padx=10, pady=(5, 15))
        self.flags_container = self.flags_scroll

        self.action_card = ctk.CTkFrame(dashboard_frame, fg_color="#1E1E22", corner_radius=12)
        self.action_card.grid(row=0, column=2, sticky="nsew", padx=(10, 0), pady=10)
        ctk.CTkLabel(self.action_card, text="AUTOMATED ACTION", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#F4F4F5").pack(anchor="w", padx=15, pady=(15, 15))

        self.action_banner = ctk.CTkFrame(self.action_card, fg_color="#3F3F46", corner_radius=10)
        self.action_banner.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.action_text = ctk.CTkLabel(self.action_banner, text="PENDING ANALYSIS", font=ctk.CTkFont(size=24, weight="bold"),
                                        text_color="#FFFFFF")
        self.action_text.pack(expand=True)

        self.sim_tab = self.tabview.tab("Simulation Sandbox")
        self.sim_tab.grid_columnconfigure(0, weight=0)  # sidebar width fixed
        self.sim_tab.grid_columnconfigure(1, weight=1)
        self.sim_tab.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self.sim_tab, width=280, fg_color="#1E1E22", corner_radius=12)
        sidebar.grid(row=0, column=0, sticky="ns", padx=(0, 15), pady=15)
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text="THREAT VECTORS 2026", font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#FFFFFF").pack(pady=(20, 15))

        threats = [
            ("💰 BEC 'Lost Wallet'", "bec_sample"),
            ("🤖 ChatGPT SaaS Failure", "chatgpt_sample"),
            ("📞 TOAD Callback Phishing", "toad_sample"),
            ("📄 HR Policy Updates", "hr_sample")
        ]

        for threat_name, method_name in threats:
            tile = ctk.CTkButton(sidebar, text=threat_name, command=lambda m=method_name: self.load_simulation_sample(m),
                                 fg_color="#252529", hover_color="#3F3F46", anchor="w", height=70,
                                 corner_radius=10, font=ctk.CTkFont(size=14), text_color="#E4E4E7")
            tile.pack(fill="x", padx=15, pady=8)

        info_frame = ctk.CTkFrame(self.sim_tab, fg_color="#1E1E22", corner_radius=12)
        info_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=15)

        ctk.CTkLabel(info_frame, text="🧪 Simulation Sandbox", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#FFFFFF").pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(info_frame, text="Click any threat tile to load a realistic phishing payload into the Live Triage tab.\n"
                                      "The system will automatically analyze the sample and show you the risk assessment.",
                     font=ctk.CTkFont(size=13), text_color="#A1A1AA", justify="left").pack(anchor="w", padx=20, pady=(0, 20))

        preview_box = ctk.CTkTextbox(info_frame, height=250, corner_radius=8, border_width=1,
                                     border_color="#3F3F46", fg_color="#252529", font=ctk.CTkFont(family="Consolas", size=11))
        preview_box.pack(fill="both", expand=True, padx=20, pady=(10, 20))
        preview_box.insert("0.0", "Select a threat vector on the left to load a sample email payload...\n\n"
                                  "The payload will be inserted into the analysis engine and the Live Triage tab will be shown.")
        self.preview_box = preview_box

        self.analyze_payload(initial=True)

    def load_simulation_sample(self, sample_key):
        samples = {
            "bec_sample": """X-Originating-IP: [192.168.1.105]
From: "CFO John Harrison" <john.harrison@legit-bank-verify.com>
To: undisclosed-recipients:;
Subject: URGENT: Wire transfer for Q3 closing

Dear Vendor,

We have an urgent wire transfer request for $287,500 due to an audit. Kindly update your bank details in the attached invoice and release payment immediately.

Best,
John Harrison
CFO, Global Investments""",

            "chatgpt_sample": """Return-Path: <support@openai-security.com>
From: OpenAI Billing <billing@openai.com>
Subject: Action Required: ChatGPT Enterprise subscription failure

Your ChatGPT Enterprise payment method has been declined. Your team's access will be suspended within 24 hours.

Click here to verify your payment: https://openai-verify.securelogin.com/auth

Failure to update will result in immediate service interruption.

Sincerely,
OpenAI Billing Team""",

            "toad_sample": """Delivered-To: victim@company.com
From: Microsoft 365 <noreply@microsoft-verify.net>
Reply-To: support-helpline@microsoft365.com
Subject: Important security alert: Callback required

We detected suspicious login from Russia. Call our helpdesk immediately: +1 (888) 321-0987
Reference ID: MSFT-ALERT-9320

Before calling, please have your employee ID ready. Do not ignore this message or your account will be locked.""",

            "hr_sample": """MIME-Version: 1.0
From: HR Department <hr@company-policies.net>
Subject: Updated 2026 Employee Policy Handbook

Dear Team,

Please review the attached HR policy update regarding remote work and PTO changes. All employees must acknowledge by Friday.

[Attachment] 2026_Employee_Handbook_Update.pdf

If you have questions, contact payroll@company-policies.net

Regards,
HR Administration"""
        }
        sample = samples.get(sample_key, "Sample not found")
        self.payload_text.delete("0.0", "end")
        self.payload_text.insert("0.0", sample)
        self.preview_box.delete("0.0", "end")
        self.preview_box.insert("0.0", sample[:800] + "\n\n[Payload injected into Live Triage engine]")
        # Switch to Live Triage tab and analyze
        self.tabview.set("Live Triage")
        self.analyze_payload()

    def analyze_payload(self, initial=False):
        text = self.payload_text.get("0.0", "end-1c").strip()
        if not text or len(text) < 10:
            if initial:
                self.risk_score_label.configure(text="0")
                self.risk_level_label.configure(text="NO DATA", text_color="#A1A1AA")
                self.progress_bar.set_value(0)
                self.action_text.configure(text="PENDING ANALYSIS")
                self.action_banner.configure(fg_color="#3F3F46")
                # Clear flags
                for widget in self.flags_container.winfo_children():
                    widget.destroy()
                return
            else:
                messagebox.showwarning("Empty Payload", "Please enter an email payload or headers for analysis.")
                return

        score = 0
        flags = []

        text_lower = text.lower()
        if re.search(r"wire transfer|bank account|password reset|verify account|confirm your login", text_lower):
            score += 35
            flags.append(("High-risk keywords detected (wire transfer, password reset)", "critical"))
        if re.search(r"bitcoin|paypal|gift card|western union", text_lower):
            score += 30
            flags.append(("Financial inducement / cryptocurrency", "critical"))
        if re.search(r"urgent|immediate action|within 24 hours|account suspended", text_lower):
            score += 20
            flags.append(("Urgency / threat of suspension", "warning"))
        if re.search(r"click here|verify now|update your payment", text_lower):
            score += 20
            flags.append(("Suspicious call to action / link", "warning"))
        if re.search(r"unusual login|suspicious activity|security alert", text_lower):
            score += 25
            flags.append(("Security alert spoofing", "warning"))
        if re.search(r"invoice attached|unexpected attachment", text_lower):
            score += 15
            flags.append(("Unexpected invoice/attachment", "warning"))
        if re.search(r"from:.*@.*(secure|verify|helpdesk|support)\..*\.(com|net)", text_lower):
            score += 10
            flags.append(("Deceptive sender domain pattern", "info"))
        # Safe patterns (reduce score slightly)
        if re.search(r"meeting agenda|weekly report|newsletter", text_lower):
            score -= 10

        score = max(0, min(100, score))
        if score >= 70:
            risk_level = "MALICIOUS"
            risk_color = "#EF4444"
            action = "ESCALATE TO SOC"
            action_color = "#7F1D1D"
        elif score >= 35:
            risk_level = "SUSPICIOUS"
            risk_color = "#F59E0B"
            action = "WARN USER & QUARANTINE"
            action_color = "#78350F"
        else:
            risk_level = "SAFE"
            risk_color = "#10B981"
            action = "CLOSE / ALLOW"
            action_color = "#064E3B"

        if not flags:
            flags.append(("No critical indicators detected", "info"))

        self.risk_score_label.configure(text=str(score))
        self.risk_level_label.configure(text=risk_level, text_color=risk_color)
        self.progress_bar.set_value(score)
        self.action_text.configure(text=action)
        self.action_banner.configure(fg_color=action_color)

        for widget in self.flags_container.winfo_children():
            widget.destroy()

        for flag_text, flag_type in flags:
            flag_row = ctk.CTkFrame(self.flags_container, fg_color="transparent")
            flag_row.pack(fill="x", pady=4)
            if flag_type == "critical":
                color = "#EF4444"
            elif flag_type == "warning":
                color = "#F59E0B"
            else:
                color = "#3B82F6"
            indicator = ctk.CTkLabel(flag_row, text="■", font=ctk.CTkFont(size=14), text_color=color)
            indicator.pack(side="left", padx=(0, 8))
            flag_label = ctk.CTkLabel(flag_row, text=flag_text, font=ctk.CTkFont(size=13), text_color="#D4D4D8",
                                      anchor="w", justify="left")
            flag_label.pack(side="left", fill="x", expand=True)

        self.last_analysis = {
            "score": score,
            "level": risk_level,
            "action": action,
            "flags": flags,
            "payload_preview": text[:500]
        }

    def copy_log_data(self):
        """Copy analysis results to clipboard."""
        if not hasattr(self, 'last_analysis') or not self.last_analysis:
            messagebox.showinfo("No Data", "Run an analysis first.")
            return
        data = self.last_analysis
        log = f"""=== PHISHING TRIAGE LOG ===
Risk Score: {data['score']}/100
Risk Level: {data['level']}
Recommended Action: {data['action']}
Telemetry Flags:
{chr(10).join(['- ' + f[0] for f in data['flags']])}
Payload Preview:
{data['payload_preview']}
==============================="""
        self.clipboard_clear()
        self.clipboard_append(log)
        messagebox.showinfo("Copied", "Log data copied to clipboard.")

if __name__ == "__main__":
    app = PhishingTriageApp()
    app.mainloop()