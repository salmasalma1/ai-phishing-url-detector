# simple_phishing_detector.py - Simple Phishing Detector (No ML Dependencies)
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import tldextract
import re
import datetime
import os
import json

LOG_FILE = "simple_phishing_logs.txt"

class SimplePhishingDetector:
    def __init__(self):
        self.setup_gui()
        self.load_malicious_domains()
        
    def load_malicious_domains(self):
        """Load known malicious domains"""
        self.malicious_domains = {
            "phishing-site.com", "malicious.net", "fake-bank.org",
            "scam-site.xyz", "suspicious-domain.tk", "paypal-verify.tk",
            "amazon-secure.com", "microsoft-login.ga", "apple-id.cf",
            "facebook-security.ml", "google-account-update.pw",
            "instagram-verify.co", "twitter-secure.tk", "linkedin-login.ml"
        }
        
        # Load additional domains from file if exists
        if os.path.exists("malicious_domains.json"):
            try:
                with open("malicious_domains.json", "r") as f:
                    additional = json.load(f)
                    self.malicious_domains.update(additional)
            except:
                pass
    
    def setup_gui(self):
        """Setup the GUI"""
        self.root = tk.Tk()
        self.root.title("🛡️ Simple Phishing Detector")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
        # Title
        title_label = tk.Label(self.root, text="🛡️ Simple Phishing URL Detector", 
                              font=("Arial", 18, "bold"), bg="#f0f0f0", fg="#2c3e50")
        title_label.pack(pady=10)
        
        # URL Entry Frame
        entry_frame = tk.Frame(self.root, bg="#f0f0f0")
        entry_frame.pack(pady=10, padx=20, fill="x")
        
        tk.Label(entry_frame, text="Enter URL to analyze:", font=("Arial", 12), bg="#f0f0f0").pack(anchor="w")
        
        self.url_entry = tk.Entry(entry_frame, font=("Arial", 12), width=70)
        self.url_entry.pack(fill="x", pady=5)
        self.url_entry.bind("<Return>", lambda e: self.analyze_url())
        
        # Buttons Frame
        buttons_frame = tk.Frame(self.root, bg="#f0f0f0")
        buttons_frame.pack(pady=10)
        
        tk.Button(buttons_frame, text="🔍 Analyze URL", command=self.analyze_url, 
                 bg="#3498db", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="🗑️ Clear", command=self.clear_all, 
                 bg="#e74c3c", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="📋 View Logs", command=self.view_logs, 
                 bg="#f39c12", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="💾 Export Logs", command=self.export_logs, 
                 bg="#27ae60", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        # Results Frame
        results_frame = tk.Frame(self.root, bg="#f0f0f0")
        results_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        tk.Label(results_frame, text="Analysis Results:", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(anchor="w")
        
        self.result_text = scrolledtext.ScrolledText(results_frame, height=20, width=80, 
                                                    font=("Courier New", 10), wrap=tk.WORD)
        self.result_text.pack(fill="both", expand=True)
        
        # Status Bar
        self.status_bar = tk.Label(self.root, text="Ready to analyze URLs", bd=1, relief=tk.SUNKEN, 
                                  anchor=tk.W, bg="#34495e", fg="white")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)
        self.root.update_idletasks()
    
    def analyze_url(self):
        """Analyze URL for phishing indicators"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL first!")
            return
        
        try:
            self.update_status("🔍 Analyzing URL...")
            
            # Normalize URL
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            
            total_score = 0
            max_score = 100
            reasons = []
            
            # 1. Check HTTP vs HTTPS
            if url.startswith("http://"):
                total_score += 25
                reasons.append("⚠️ Uses HTTP instead of HTTPS (insecure)")
            
            # 2. Check URL length
            if len(url) > 75:
                total_score += 20
                reasons.append("⚠️ URL is excessively long")
            elif len(url) > 50:
                total_score += 10
                reasons.append("⚠️ URL is unusually long")
            
            # 3. Check for IP address
            ip_pattern = re.compile(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            if ip_pattern.match(url):
                total_score += 30
                reasons.append("🚨 Uses IP address instead of domain name")
            
            # 4. Check domain reputation
            parsed = tldextract.extract(url)
            domain = f"{parsed.domain}.{parsed.suffix}".lower()
            
            if domain in self.malicious_domains:
                total_score += 40
                reasons.append(f"🚨 Domain found in malicious database: {domain}")
            
            # 5. Check for suspicious keywords
            suspicious_keywords = [
                'login', 'secure', 'account', 'update', 'verify', 'banking', 
                'paypal', 'amazon', 'webscr', 'signin', 'password', 'confirm',
                'token', 'auth', 'authentication', 'security', 'protect'
            ]
            
            url_lower = url.lower()
            main_domain = parsed.domain.lower()
            found_keywords = []
            
            for keyword in suspicious_keywords:
                if keyword in url_lower and keyword not in main_domain:
                    found_keywords.append(keyword)
            
            if found_keywords:
                total_score += 20
                reasons.append(f"⚠️ Suspicious keywords: {', '.join(found_keywords)}")
            
            # 6. Check for special characters
            special_chars = ['@', '%', '--', '..', '..', '__']
            found_chars = [char for char in special_chars if char in url_lower]
            
            if found_chars:
                total_score += 15
                reasons.append(f"⚠️ Contains suspicious characters: {', '.join(found_chars)}")
            
            # 7. Check subdomain count
            subdomain_parts = parsed.subdomain.split('.') if parsed.subdomain else []
            if len(subdomain_parts) > 3:
                total_score += 15
                reasons.append("⚠️ Too many subdomains")
            elif len(subdomain_parts) > 1:
                total_score += 5
                reasons.append("⚠️ Multiple subdomains")
            
            # 8. Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
            if parsed.suffix in suspicious_tlds:
                total_score += 10
                reasons.append(f"⚠️ Uses suspicious TLD: .{parsed.suffix}")
            
            # 9. Check for brand impersonation
            brands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal', 
                     'instagram', 'twitter', 'linkedin', 'netflix', 'spotify']
            
            brand_in_subdomain = False
            if parsed.subdomain:
                for brand in brands:
                    if brand in parsed.subdomain.lower() and brand != main_domain:
                        brand_in_subdomain = True
                        break
            
            if brand_in_subdomain:
                total_score += 25
                reasons.append("🚨 Possible brand impersonation in subdomain")
            
            # 10. Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
            if any(shortener in url for shortener in shorteners):
                total_score += 10
                reasons.append("⚠️ Uses URL shortener (may hide malicious content)")
            
            # Cap the score
            final_score = min(total_score, max_score)
            
            # Display results
            self.display_results(url, final_score, reasons)
            
            # Log the analysis
            self.log_analysis(url, final_score)
            
            self.update_status("✅ Analysis complete!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {e}")
            self.update_status("❌ Analysis failed!")
    
    def display_results(self, url, score, reasons):
        """Display analysis results"""
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"URL: {url}\n\n")
        self.result_text.insert(tk.END, f"Phishing Risk Score: {score}/100\n\n")
        
        if score >= 70:
            color = "red"
            verdict = "🚨 HIGH RISK: Very likely to be a Phishing URL!"
            recommendation = "❌ DO NOT CLICK - This appears to be a phishing attempt!"
        elif score >= 40:
            color = "orange"
            verdict = "⚠️ MEDIUM RISK: Suspicious URL"
            recommendation = "⚠️ Proceed with extreme caution!"
        else:
            color = "green"
            verdict = "✅ LOW RISK: Appears relatively safe"
            recommendation = "✅ URL appears safe, but always stay vigilant!"
        
        self.result_text.insert(tk.END, verdict + "\n\n")
        self.result_text.insert(tk.END, f"Recommendation: {recommendation}\n\n")
        
        if reasons:
            self.result_text.insert(tk.END, "Risk Factors Found:\n")
            for i, reason in enumerate(reasons, 1):
                self.result_text.insert(tk.END, f"{i}. {reason}\n")
        else:
            self.result_text.insert(tk.END, "✅ No suspicious indicators detected\n")
        
        # Format verdict
        self.result_text.tag_add("verdict", "3.0", "3.end")
        self.result_text.tag_config("verdict", foreground=color, font=("Arial", 14, "bold"))
        
        # Format recommendation
        self.result_text.tag_add("recommendation", "4.0", "4.end")
        self.result_text.tag_config("recommendation", foreground=color, font=("Arial", 11, "bold"))
    
    def log_analysis(self, url, score):
        """Log analysis results"""
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                risk_level = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
                f.write(f"[{timestamp}] {url} | Score: {score}/100 | Risk: {risk_level}\n")
        except Exception as e:
            print(f"Failed to log analysis: {e}")
    
    def clear_all(self):
        """Clear all fields"""
        self.url_entry.delete(0, tk.END)
        self.result_text.delete(1.0, tk.END)
        self.update_status("Ready to analyze URLs")
    
    def view_logs(self):
        """View analysis logs"""
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("Logs", "No logs found yet.")
            return
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "=== Analysis History ===\n\n")
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = f.read()
                self.result_text.insert(tk.END, logs)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read logs: {e}")
    
    def export_logs(self):
        """Export logs to file"""
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
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

# Main execution
if __name__ == "__main__":
    app = SimplePhishingDetector()
    app.run()
