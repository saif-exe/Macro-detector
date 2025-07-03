import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import hashlib, os
from stegano import lsb
from oletools.olevba import VBA_Parser
import magic
from datetime import datetime
import pygame

pygame.mixer.init()
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def compute_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def detect_mime_type(file_path):
    return magic.Magic(mime=True).from_file(file_path)

def detect_steganography(file_path):
    try:
        if not file_path.lower().endswith((".png", ".bmp")):
            return False, "Unsupported image format for stego analysis (use PNG or BMP)."

        img = Image.open(file_path)
        rgb_path = file_path + "_temp_rgb.png"
        img.convert("RGB").save(rgb_path)

        secret = lsb.reveal(rgb_path)
        os.remove(rgb_path)

        return (True, secret) if secret else (False, "No hidden data found.")
    except Exception as e:
        return False, f"Stego error: {e}"

def ransomware_trace(secret):
    keywords = ["ransom", "bitcoin", "wallet", "key=", "decrypt", "aes", ".onion"]
    for word in keywords:
        if word in secret.lower():
            return True, f"⚠️ Ransomware indicator: {word}"
    return False, "✅ No ransomware indicators."

def scan_macros(file_path):
    logs = []
    try:
        vba = VBA_Parser(file_path)
        if vba.detect_vba_macros():
            logs.append("✅ Macros found. Extracting code...")
            for (_, stream_path, filename, code) in vba.extract_macros():
                logs.append(f"\n--- Macro: {filename or 'Unnamed'} ---\n{code[:1000]}")
                if any(k in code.lower() for k in ["shell", "powershell", "autoopen", "createobject"]):
                    logs.append("⚠️ Suspicious macro behavior detected.")
            return logs, "Threat Detected"
        else:
            logs.append("✅ No macros found.")
            return logs, "Clean"
    except Exception as e:
        return [f"Macro scan failed: {e}"], "Scan Error"

def scan_log_file(path):
    indicators = ["bitcoin", "wallet", "decrypt", ".onion", "tor", "aes", "key="]
    lolbins = ["powershell.exe", "certutil.exe", "regsvr32.exe", "mshta.exe"]
    log = []
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read().lower()
            found = False
            for ioc in indicators + lolbins:
                if ioc in content:
                    found = True
                    log.append(f"⚠️ IOC: {ioc}")
            if not found:
                log.append("✅ No suspicious content.")
            return log, "Threat Detected" if found else "Clean"
    except Exception as e:
        return [f"Log read failed: {e}"], "Scan Error"

def full_scan_pipeline(path):
    logs = [f"Scanning: {os.path.basename(path)}", f"SHA256: {compute_file_hash(path)}"]
    mime = detect_mime_type(path)
    logs.append(f"MIME: {mime}")
    ext = os.path.splitext(path)[-1].lower()

    if mime.startswith("image"):
        steg_found, steg_msg = detect_steganography(path)
        logs.append("✅ Stego detected!" if steg_found else "❌ No stego found.")
        if steg_found:
            logs.append(f"Stego Message: {steg_msg[:100]}..." if len(steg_msg) > 100 else steg_msg)
            r_found, r_msg = ransomware_trace(steg_msg)
            logs.append(r_msg)
            return logs, "Threat Detected" if r_found else "Clean"
        else:
            logs.append(steg_msg)
            return logs, "Clean"

    elif ext in [".xlsm", ".docm"]:
        macro_logs, status = scan_macros(path)
        logs.extend(macro_logs)
        return logs, status

    elif ext in [".log", ".txt"]:
        log_lines, status = scan_log_file(path)
        logs.extend(log_lines)
        return logs, status

    logs.append("❌ Unsupported file type.")
    return logs, "Unsupported"

class RansomwareScanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Ransomware Forensic Scanner")
        self.geometry("1000x700")
        self.file_path = ""
        self.scan_history = []
        self.build_gui()

    def build_gui(self):
        tabs = ctk.CTkTabview(self)
        tabs.pack(padx=20, pady=20, expand=True, fill="both")
        scan_tab = tabs.add("Scanner")
        preview_tab = tabs.add("Preview")
        history_tab = tabs.add("History")

        ctk.CTkLabel(scan_tab, text="Select and Scan Files", font=("Segoe UI", 22, "bold")).pack(pady=10)
        ctk.CTkButton(scan_tab, text="Choose File", command=self.select_file).pack(pady=10)
        self.file_label = ctk.CTkLabel(scan_tab, text="No file selected")
        self.file_label.pack()
        ctk.CTkButton(scan_tab, text="Start Scan", fg_color="green", command=self.run_scan).pack(pady=10)
        self.progress = ctk.CTkProgressBar(scan_tab, width=500)
        self.progress.set(0)
        self.progress.pack(pady=10)
        self.status_label = ctk.CTkLabel(scan_tab, text="Status: Idle", font=("Segoe UI", 16))
        self.status_label.pack(pady=5)
        self.log_box = ctk.CTkTextbox(scan_tab, width=850, height=300)
        self.log_box.pack(pady=10)

        self.preview_box = ctk.CTkTextbox(preview_tab, width=850, height=500)
        self.preview_box.pack(pady=10)

        self.history_box = ctk.CTkTextbox(history_tab, width=850, height=500)
        self.history_box.pack(pady=10)
        ctk.CTkButton(history_tab, text="Export Last Report", command=self.export_report).pack(pady=10)

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("Supported", "*.png *.jpg *.jpeg *.bmp *.xlsm *.docm *.log *.txt")])
        if path:
            self.file_path = path
            self.file_label.configure(text=os.path.basename(path))
            self.preview_box.delete("0.0", "end")
            if path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
                try:
                    img = Image.open(path).resize((250, 250), Image.Resampling.LANCZOS)
                    img_tk = ImageTk.PhotoImage(img)
                    self.preview_box.image_create("end", image=img_tk)
                    self.preview_box.image = img_tk
                except:
                    self.preview_box.insert("0.0", "Image preview failed.")
            else:
                with open(path, 'r', errors='ignore') as f:
                    self.preview_box.insert("0.0", f.read(3000))

    def run_scan(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first.")
            return
        self.status_label.configure(text="Scanning...", text_color="orange")
        self.progress.set(0.3)
        self.update()
        logs, status = full_scan_pipeline(self.file_path)
        self.progress.set(1.0)

        try:
            pygame.mixer.Sound("/usr/share/sounds/freedesktop/stereo/complete.oga").play()
        except:
            pass

        self.log_box.delete("0.0", "end")
        for line in logs:
            self.log_box.insert("end", f"{line}\n")

        color = "red" if "Threat" in status else ("orange" if "Unsupported" in status else "green")
        self.status_label.configure(text=f"Status: {status}", text_color=color)
        entry = f"{os.path.basename(self.file_path)} - {status}"
        self.scan_history.append(entry)
        self.update_history()

    def update_history(self):
        self.history_box.delete("0.0", "end")
        for entry in self.scan_history:
            self.history_box.insert("end", f"{entry}\n")

    def export_report(self):
        if not self.file_path:
            messagebox.showinfo("Export", "No scan to export.")
            return
        name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=name)
        if path:
            with open(path, "w") as f:
                f.write(self.log_box.get("0.0", "end"))
            messagebox.showinfo("Export", f"Report saved as {path}")

if __name__ == "__main__":
    app = RansomwareScanner()
    app.mainloop()

