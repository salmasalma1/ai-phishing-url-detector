# main.py - AI-Powered Phishing URL Detector with Extra Buttons
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import tldextract
import re
import datetime
import os

LOG_FILE = "phishing_logs.txt"

def analyze_with_ai(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    total_weight = 0
    reasons = []
    
    if url.startswith("http://"):
        total_weight += 25
        reasons.append("⚠️ Insecure connection: Uses HTTP instead of HTTPS")
    
    if len(url) > 75:
        total_weight += 20
        reasons.append("⚠️ Suspicious: URL is excessively long")
    
    if url.count('.') > 4:
        total_weight += 15
        reasons.append("⚠️ Suspicious: Too many subdomains or dots")
    
    suspicious_words = ['login', 'secure', 'account', 'update', 'verify', 'banking', 
                        'paypal', 'amazon', 'webscr', 'signin', 'password', 'confirm']
    lower_url = url.lower()
    parsed = tldextract.extract(url)
    main_domain = parsed.domain.lower()
    for word in suspicious_words:
        if word in lower_url and word not in main_domain:
            total_weight += 20
            reasons.append(f"⚠️ Suspicious keyword detected: '{word}'")
            break
    
    if '@' in url or '%2' in lower_url or '--' in lower_url:
        total_weight += 15
        reasons.append("⚠️ Suspicious: Contains special symbols or encoding")
    
    ip_pattern = re.compile(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.match(url.lower()):
        total_weight += 30
        reasons.append("🚨 High risk: Uses IP address instead of domain name")
    
    ai_probability = min(total_weight, 100)
    
    return url, ai_probability, reasons

def analyze_url():
    url = entry.get().strip()
    if not url:
        messagebox.showwarning("Warning", "Please enter a URL first!")
        return
    
    try:
        clean_url, ai_prob, reasons = analyze_with_ai(url)
        
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"URL: {clean_url}\n\n")
        result_text.insert(tk.END, f"AI Phishing Probability: {ai_prob:.1f}%\n\n")
        
        if ai_prob >= 70:
            color = "red"
            verdict = "🚨 HIGH RISK: Very likely to be a Phishing URL!"
        elif ai_prob >= 40:
            color = "orange"
            verdict = "⚠️ CAUTION: Suspicious URL – Do not click!"
        else:
            color = "green"
            verdict = "✅ LOW RISK: Appears relatively safe"
        
        result_text.insert(tk.END, verdict + "\n\n")
        result_text.insert(tk.END, "AI Analysis Details:\n")
        if reasons:
            for r in reasons:
                result_text.insert(tk.END, r + "\n")
        else:
            result_text.insert(tk.END, "No suspicious indicators detected\n")
        
        result_text.tag_add("verdict", "3.0", "3.end")
        result_text.tag_config("verdict", foreground=color, font=("Arial", 14, "bold"))
        
        # Save to log
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now()}] {clean_url} | AI Probability: {ai_prob:.1f}% | {verdict}\n")
            
    except Exception as e:
        messagebox.showerror("Error", "Invalid URL or analysis error.")

def clear_all():
    entry.delete(0, tk.END)
    result_text.delete(1.0, tk.END)

def view_logs():
    if not os.path.exists(LOG_FILE):
        messagebox.showinfo("Logs", "No logs found yet.")
        return
    
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "=== Previous Analysis Logs ===\n\n")
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.read()
            result_text.insert(tk.END, logs)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read logs: {e}")

def export_logs():
    if not os.path.exists(LOG_FILE):
        messagebox.showinfo("Export", "No logs to export.")
        return
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as src, open(file_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
            messagebox.showinfo("Export", f"Logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")

def check_domain_reputation(url):
    """Check domain reputation against known malicious domains"""
    try:
        parsed = tldextract.extract(url)
        domain = f"{parsed.domain}.{parsed.suffix}"
        
        # Known malicious domains (simplified database)
        known_malicious = [
            "phishing-site.com", "malicious.net", "fake-bank.org",
            "scam-site.xyz", "suspicious-domain.tk"
        ]
        
        if domain in known_malicious:
            return True, "Domain found in malicious database"
        
        return False, "Domain not found in malicious database"
    except:
        return False, "Unable to check domain reputation"

# Create main window
root = tk.Tk()
root.title("🛡️ AI Phishing Detector Pro")
root.geometry("800x600")
root.configure(bg="#f0f0f0")

# Title
title_label = tk.Label(root, text="🛡️ AI-Powered Phishing URL Detector", 
                       font=("Arial", 18, "bold"), bg="#f0f0f0", fg="#2c3e50")
title_label.pack(pady=10)

# URL Entry Frame
entry_frame = tk.Frame(root, bg="#f0f0f0")
entry_frame.pack(pady=10, padx=20, fill="x")

tk.Label(entry_frame, text="Enter URL to analyze:", font=("Arial", 12), bg="#f0f0f0").pack(anchor="w")
entry = tk.Entry(entry_frame, font=("Arial", 12), width=70)
entry.pack(fill="x", pady=5)
entry.bind("<Return>", lambda e: analyze_url())

# Buttons Frame
buttons_frame = tk.Frame(root, bg="#f0f0f0")
buttons_frame.pack(pady=10)

tk.Button(buttons_frame, text="🔍 Analyze URL", command=analyze_url, 
          bg="#3498db", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)

tk.Button(buttons_frame, text="🗑️ Clear", command=clear_all, 
          bg="#e74c3c", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)

tk.Button(buttons_frame, text="📋 View Logs", command=view_logs, 
          bg="#f39c12", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)

tk.Button(buttons_frame, text="💾 Export Logs", command=export_logs, 
          bg="#27ae60", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)

# Results Frame
results_frame = tk.Frame(root, bg="#f0f0f0")
results_frame.pack(pady=10, padx=20, fill="both", expand=True)

tk.Label(results_frame, text="Analysis Results:", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(anchor="w")

result_text = scrolledtext.ScrolledText(results_frame, height=20, width=80, 
                                       font=("Courier New", 10), wrap=tk.WORD)
result_text.pack(fill="both", expand=True)

# Status Bar
status_bar = tk.Label(root, text="Ready to analyze URLs", bd=1, relief=tk.SUNKEN, 
                     anchor=tk.W, bg="#34495e", fg="white")
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

def update_status(message):
    status_bar.config(text=message)
    root.update_idletasks()

# Enhanced analyze_url function with status updates
def enhanced_analyze_url():
    url = entry.get().strip()
    if not url:
        messagebox.showwarning("Warning", "Please enter a URL first!")
        return
    
    try:
        update_status("🔍 Analyzing URL with AI...")
        clean_url, ai_prob, reasons = analyze_with_ai(url)
        
        update_status("🔍 Checking domain reputation...")
        is_malicious, rep_message = check_domain_reputation(url)
        if is_malicious:
            ai_prob = min(ai_prob + 30, 100)
            reasons.append(f"🚨 {rep_message}")
        
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"URL: {clean_url}\n\n")
        result_text.insert(tk.END, f"AI Phishing Probability: {ai_prob:.1f}%\n\n")
        
        if ai_prob >= 70:
            color = "red"
            verdict = "🚨 HIGH RISK: Very likely to be a Phishing URL!"
        elif ai_prob >= 40:
            color = "orange"
            verdict = "⚠️ CAUTION: Suspicious URL – Do not click!"
        else:
            color = "green"
            verdict = "✅ LOW RISK: Appears relatively safe"
        
        result_text.insert(tk.END, verdict + "\n\n")
        result_text.insert(tk.END, "AI Analysis Details:\n")
        if reasons:
            for r in reasons:
                result_text.insert(tk.END, r + "\n")
        else:
            result_text.insert(tk.END, "No suspicious indicators detected\n")
        
        result_text.tag_add("verdict", "3.0", "3.end")
        result_text.tag_config("verdict", foreground=color, font=("Arial", 14, "bold"))
        
        # Save to log
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now()}] {clean_url} | AI Probability: {ai_prob:.1f}% | {verdict}\n")
        
        update_status("✅ Analysis complete!")
            
    except Exception as e:
        messagebox.showerror("Error", f"Invalid URL or analysis error: {e}")
        update_status("❌ Analysis failed!")

# Replace the original analyze_url function
analyze_url = enhanced_analyze_url

# Start the GUI
if __name__ == "__main__":
    root.mainloop()