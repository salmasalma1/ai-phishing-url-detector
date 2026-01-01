# enhanced_phishing_detector.py - Advanced AI Phishing Detector with ML Integration
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import tldextract
import re
import datetime
import os
import threading
import requests
from urllib.parse import urlparse
import json
from ml_phishing_detector import MLPhishingDetector

# Enhanced logging
LOG_FILE = "enhanced_phishing_logs.txt"
ML_MODEL_FILE = "phishing_model.pkl"

class EnhancedPhishingDetector:
    def __init__(self):
        self.ml_detector = MLPhishingDetector()
        self.setup_gui()
        self.load_models()
        
    def load_models(self):
        """Load ML models in background"""
        def load_in_background():
            try:
                self.update_status("🤖 Loading ML models...")
                self.ml_detector.load_model()
                self.update_status("✅ Ready to analyze URLs")
            except Exception as e:
                self.update_status(f"⚠️ ML model loading failed: {e}")
        
        threading.Thread(target=load_in_background, daemon=True).start()
    
    def setup_gui(self):
        """Setup the enhanced GUI"""
        self.root = tk.Tk()
        self.root.title("🛡️ Advanced AI Phishing Detector Pro")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        
        # Title
        title_label = tk.Label(self.root, text="🛡️ Advanced AI Phishing Detector", 
                              font=("Arial", 20, "bold"), bg="#f0f0f0", fg="#2c3e50")
        title_label.pack(pady=10)
        
        # Subtitle
        subtitle_label = tk.Label(self.root, text="Machine Learning + Rule-Based Detection", 
                                 font=("Arial", 12), bg="#f0f0f0", fg="#7f8c8d")
        subtitle_label.pack()
        
        # URL Entry Frame
        entry_frame = tk.Frame(self.root, bg="#f0f0f0")
        entry_frame.pack(pady=10, padx=20, fill="x")
        
        tk.Label(entry_frame, text="Enter URL to analyze:", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(anchor="w")
        
        # URL Entry with suggestions
        self.url_entry = tk.Entry(entry_frame, font=("Arial", 12), width=80)
        self.url_entry.pack(fill="x", pady=5)
        self.url_entry.bind("<Return>", lambda e: self.analyze_url())
        
        # Detection Mode Selection
        mode_frame = tk.Frame(self.root, bg="#f0f0f0")
        mode_frame.pack(pady=5)
        
        tk.Label(mode_frame, text="Detection Mode:", font=("Arial", 11, "bold"), bg="#f0f0f0").pack(side="left", padx=5)
        
        self.detection_mode = tk.StringVar(value="both")
        tk.Radiobutton(mode_frame, text="Rule-Based", variable=self.detection_mode, value="rule", 
                      bg="#f0f0f0", font=("Arial", 10)).pack(side="left", padx=5)
        tk.Radiobutton(mode_frame, text="Machine Learning", variable=self.detection_mode, value="ml", 
                      bg="#f0f0f0", font=("Arial", 10)).pack(side="left", padx=5)
        tk.Radiobutton(mode_frame, text="Both (Recommended)", variable=self.detection_mode, value="both", 
                      bg="#f0f0f0", font=("Arial", 10)).pack(side="left", padx=5)
        
        # Buttons Frame
        buttons_frame = tk.Frame(self.root, bg="#f0f0f0")
        buttons_frame.pack(pady=10)
        
        tk.Button(buttons_frame, text="🔍 Analyze URL", command=self.analyze_url, 
                 bg="#3498db", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="🗑️ Clear", command=self.clear_all, 
                 bg="#e74c3c", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="📊 View Logs", command=self.view_logs, 
                 bg="#f39c12", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="💾 Export Logs", command=self.export_logs, 
                 bg="#27ae60", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        tk.Button(buttons_frame, text="⚙️ Settings", command=self.show_settings, 
                 bg="#8e44ad", fg="white", font=("Arial", 12, "bold"), padx=20).pack(side="left", padx=5)
        
        # Progress Bar
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(pady=5, padx=20, fill="x")
        
        # Results Frame with tabs
        results_frame = tk.Frame(self.root, bg="#f0f0f0")
        results_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Analysis Tab
        analysis_tab = tk.Frame(self.notebook)
        self.notebook.add(analysis_tab, text="🔍 Analysis")
        
        tk.Label(analysis_tab, text="Analysis Results:", font=("Arial", 12, "bold"), bg="white").pack(anchor="w", padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(analysis_tab, height=20, width=80, 
                                                    font=("Courier New", 10), wrap=tk.WORD)
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Features Tab
        features_tab = tk.Frame(self.notebook)
        self.notebook.add(features_tab, text="📊 Features")
        
        tk.Label(features_tab, text="Feature Analysis:", font=("Arial", 12, "bold"), bg="white").pack(anchor="w", padx=5, pady=5)
        
        self.features_text = scrolledtext.ScrolledText(features_tab, height=20, width=80, 
                                                      font=("Courier New", 10), wrap=tk.WORD)
        self.features_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Status Bar
        self.status_bar = tk.Label(self.root, text="Ready to analyze URLs", bd=1, relief=tk.SUNKEN, 
                                  anchor=tk.W, bg="#34495e", fg="white")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)
        self.root.update_idletasks()
    
    def analyze_with_rules(self, url):
        """Original rule-based analysis"""
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
        
        rule_probability = min(total_weight, 100)
        return url, rule_probability, reasons
    
    def analyze_with_ml(self, url):
        """Machine learning analysis"""
        try:
            prediction, probability = self.ml_detector.predict_url(url)
            ml_probability = probability * 100
            
            if prediction == 1:
                reasons = ["🤖 ML Model: Detected as phishing"]
            else:
                reasons = ["✅ ML Model: Detected as legitimate"]
            
            return url, ml_probability, reasons
        except Exception as e:
            return url, 0, [f"❌ ML Analysis failed: {e}"]
    
    def analyze_url(self):
        """Main analysis function"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL first!")
            return
        
        # Start progress bar
        self.progress.start()
        
        def analyze_in_background():
            try:
                self.update_status("🔍 Analyzing URL...")
                
                mode = self.detection_mode.get()
                
                if mode == "rule":
                    clean_url, rule_prob, rule_reasons = self.analyze_with_rules(url)
                    final_prob = rule_prob
                    all_reasons = rule_reasons
                    method = "Rule-Based Analysis"
                    
                elif mode == "ml":
                    clean_url, ml_prob, ml_reasons = self.analyze_with_ml(url)
                    final_prob = ml_prob
                    all_reasons = ml_reasons
                    method = "Machine Learning Analysis"
                    
                else:  # both
                    self.update_status("🔍 Running rule-based analysis...")
                    clean_url, rule_prob, rule_reasons = self.analyze_with_rules(url)
                    
                    self.update_status("🤖 Running ML analysis...")
                    _, ml_prob, ml_reasons = self.analyze_with_ml(url)
                    
                    # Combine results (weighted average)
                    final_prob = (rule_prob * 0.6 + ml_prob * 0.4)
                    all_reasons = rule_reasons + ml_reasons
                    method = "Hybrid Analysis (Rules + ML)"
                
                # Display results
                self.display_results(clean_url, final_prob, all_reasons, method)
                
                # Log the analysis
                self.log_analysis(clean_url, final_prob, method)
                
                self.update_status("✅ Analysis complete!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Analysis failed: {e}")
                self.update_status("❌ Analysis failed!")
            finally:
                self.progress.stop()
        
        threading.Thread(target=analyze_in_background, daemon=True).start()
    
    def display_results(self, url, probability, reasons, method):
        """Display analysis results"""
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"URL: {url}\n\n")
        self.result_text.insert(tk.END, f"Detection Method: {method}\n\n")
        self.result_text.insert(tk.END, f"Phishing Probability: {probability:.1f}%\n\n")
        
        if probability >= 70:
            color = "red"
            verdict = "🚨 HIGH RISK: Very likely to be a Phishing URL!"
        elif probability >= 40:
            color = "orange"
            verdict = "⚠️ CAUTION: Suspicious URL – Do not click!"
        else:
            color = "green"
            verdict = "✅ LOW RISK: Appears relatively safe"
        
        self.result_text.insert(tk.END, verdict + "\n\n")
        self.result_text.insert(tk.END, "Analysis Details:\n")
        for reason in reasons:
            self.result_text.insert(tk.END, reason + "\n")
        
        # Format verdict
        self.result_text.tag_add("verdict", "4.0", "4.end")
        self.result_text.tag_config("verdict", foreground=color, font=("Arial", 14, "bold"))
        
        # Show feature analysis if ML was used
        if "ML" in method:
            self.show_feature_analysis(url)
    
    def show_feature_analysis(self, url):
        """Show detailed feature analysis"""
        try:
            features = self.ml_detector.extract_features(url)
            
            self.features_text.delete(1.0, tk.END)
            self.features_text.insert(tk.END, f"Feature Analysis for: {url}\n\n")
            
            for feature, value in features.items():
                self.features_text.insert(tk.END, f"{feature}: {value}\n")
            
            # Show feature importance if available
            importance = self.ml_detector.get_feature_importance()
            if importance:
                self.features_text.insert(tk.END, "\nFeature Importance (Top 10):\n")
                sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]
                for feature, score in sorted_features:
                    self.features_text.insert(tk.END, f"{feature}: {score:.3f}\n")
        
        except Exception as e:
            self.features_text.delete(1.0, tk.END)
            self.features_text.insert(tk.END, f"Feature analysis failed: {e}")
    
    def log_analysis(self, url, probability, method):
        """Log analysis results"""
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {url} | {method} | Probability: {probability:.1f}%\n")
        except Exception as e:
            print(f"Failed to log analysis: {e}")
    
    def clear_all(self):
        """Clear all fields"""
        self.url_entry.delete(0, tk.END)
        self.result_text.delete(1.0, tk.END)
        self.features_text.delete(1.0, tk.END)
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
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as src, open(file_path, "w", encoding="utf-8") as dst:
                    dst.write(src.read())
                messagebox.showinfo("Export", f"Logs exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {e}")
    
    def show_settings(self):
        """Show settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ Settings")
        settings_window.geometry("400x300")
        settings_window.configure(bg="#f0f0f0")
        
        tk.Label(settings_window, text="Detection Settings", font=("Arial", 14, "bold"), 
                bg="#f0f0f0").pack(pady=10)
        
        # Threshold setting
        tk.Label(settings_window, text="Phishing Threshold (%):", font=("Arial", 11), 
                bg="#f0f0f0").pack(pady=5)
        
        threshold_var = tk.IntVar(value=50)
        threshold_scale = tk.Scale(settings_window, from_=0, to=100, orient=tk.HORIZONTAL, 
                                 variable=threshold_var, length=300)
        threshold_scale.pack(pady=5)
        
        # Model info
        tk.Label(settings_window, text="Model Information:", font=("Arial", 11, "bold"), 
                bg="#f0f0f0").pack(pady=10)
        
        info_text = tk.Text(settings_window, height=8, width=50, font=("Courier New", 9))
        info_text.pack(pady=5, padx=10)
        
        info_text.insert(tk.END, "ML Model Status: " + ("Trained" if self.ml_detector.is_trained else "Not Trained") + "\n")
        info_text.insert(tk.END, "Features Used: " + str(len(self.ml_detector.extract_features("https://example.com"))) + "\n")
        info_text.insert(tk.END, "Algorithm: Random Forest\n")
        info_text.insert(tk.END, "Training Data: Synthetic + Real Examples\n")
        info_text.config(state=tk.DISABLED)
        
        # Close button
        tk.Button(settings_window, text="Close", command=settings_window.destroy, 
                 bg="#3498db", fg="white", font=("Arial", 10, "bold")).pack(pady=10)
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

# Main execution
if __name__ == "__main__":
    app = EnhancedPhishingDetector()
    app.run()
