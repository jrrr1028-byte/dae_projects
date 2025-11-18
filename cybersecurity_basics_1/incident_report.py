import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from datetime import datetime
from collections import defaultdict

# Main Application Class
class SecurityLogAnalyzer:
    def __init__(self, root):
        """Initialize the GUI application"""
        self.root = root
        self.root.title("Security Log Analyzer - Incident Response Tool")
        self.root.geometry("1000x750")
        
        # Variables to store analysis data
        self.log_data = []
        self.failed_attempts = defaultdict(int)  # Track failed attempts per IP
        self.total_logins = 0
        self.failed_logins = 0
        
        # Create GUI components
        self.create_widgets()
    
    def create_widgets(self):
        """Create all GUI elements"""
        # Title Label
        title_label = tk.Label(
            self.root, 
            text="🔒 Security Log Analyzer", 
            font=("Helvetica", 18, "bold"),
            bg="#2c3e50",
            fg="white",
            pady=15
        )
        title_label.pack(fill=tk.X)
        
        # Button Frame
        button_frame = tk.Frame(self.root, bg="white", pady=15)
        button_frame.pack(fill=tk.X)
        
        # Load Log Button
        self.load_btn = tk.Button(
            button_frame,
            text="📂 Load Log File",
            command=self.load_log_file,
            font=("Helvetica", 11, "bold"),
            bg="#27ae60",
            fg="white",
            padx=25,
            pady=12,
            relief=tk.RAISED,
            borderwidth=3,
            cursor="hand2"
        )
        self.load_btn.pack(side=tk.LEFT, padx=10)
        
        # Analyze Button
        self.analyze_btn = tk.Button(
            button_frame,
            text="🔍 Analyze Logs",
            command=self.analyze_logs,
            font=("Helvetica", 11, "bold"),
            bg="#3498db",
            fg="white",
            padx=25,
            pady=12,
            relief=tk.RAISED,
            borderwidth=3,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=10)
        
        # Clear Button
        self.clear_btn = tk.Button(
            button_frame,
            text="🗑️ Clear",
            command=self.clear_all,
            font=("Helvetica", 11, "bold"),
            bg="#e74c3c",
            fg="white",
            padx=25,
            pady=12,
            relief=tk.RAISED,
            borderwidth=3,
            cursor="hand2"
        )
        self.clear_btn.pack(side=tk.LEFT, padx=10)
        
        # Stats Frame
        stats_frame = tk.Frame(self.root, bg="#ecf0f1", relief=tk.GROOVE, borderwidth=3)
        stats_frame.pack(pady=10, padx=20, fill=tk.X)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="📊 Statistics: No logs loaded",
            font=("Courier", 10, "bold"),
            bg="#ecf0f1",
            fg="#2c3e50",
            justify=tk.LEFT,
            padx=15,
            pady=15
        )
        self.stats_label.pack(fill=tk.X)
        
        # Log Display Area
        log_frame = tk.Frame(self.root, bg="white")
        log_frame.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)
        
        log_label = tk.Label(
            log_frame,
            text="Log Contents:",
            font=("Helvetica", 11, "bold"),
            bg="white",
            fg="#2c3e50",
            anchor=tk.W
        )
        log_label.pack(fill=tk.X, pady=(0, 5))
        
        self.log_display = scrolledtext.ScrolledText(
            log_frame,
            width=110,
            height=12,
            font=("Courier", 9),
            bg="#f8f9fa",
            fg="#212529",
            relief=tk.SUNKEN,
            borderwidth=2,
            wrap=tk.WORD
        )
        self.log_display.pack(fill=tk.BOTH, expand=True)
        
        # Alerts Display Area
        alert_frame = tk.Frame(self.root, bg="white")
        alert_frame.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)
        
        alert_label = tk.Label(
            alert_frame,
            text="🚨 Security Alerts:",
            font=("Helvetica", 11, "bold"),
            bg="white",
            fg="#c0392b",
            anchor=tk.W
        )
        alert_label.pack(fill=tk.X, pady=(0, 5))
        
        self.alert_display = scrolledtext.ScrolledText(
            alert_frame,
            width=110,
            height=10,
            font=("Courier", 9, "bold"),
            bg="#fff5f5",
            fg="#c0392b",
            relief=tk.SUNKEN,
            borderwidth=2,
            wrap=tk.WORD
        )
        self.alert_display.pack(fill=tk.BOTH, expand=True)
    
    def load_log_file(self):
        """Load and display log file"""
        # Open file dialog to select log file
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                # Read the log file
                with open(file_path, 'r') as file:
                    self.log_data = file.readlines()
                
                # Display logs in the text area
                self.log_display.delete(1.0, tk.END)
                self.log_display.insert(tk.END, ''.join(self.log_data))
                
                # Enable analyze button
                self.analyze_btn.config(state=tk.NORMAL, bg="#2980b9")
                
                # Update stats
                self.stats_label.config(
                    text=f"📊 Statistics: Loaded {len(self.log_data)} log entries from file"
                )
                
                messagebox.showinfo("Success", f"✅ Loaded {len(self.log_data)} log entries successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"❌ Failed to load file:\n{str(e)}")
    
    def parse_log_line(self, line):
        """Parse a single log line and extract information"""
        try:
            # Split the log line by ' | '
            parts = line.strip().split(' | ')
            
            if len(parts) >= 4:
                timestamp = parts[0]
                status = parts[1]
                user = parts[2].replace('user: ', '')
                ip = parts[3].replace('IP: ', '')
                
                return {
                    'timestamp': timestamp,
                    'status': status,
                    'user': user,
                    'ip': ip
                }
        except:
            pass
        return None
    
    def analyze_logs(self):
        """Analyze logs for security threats"""
        if not self.log_data:
            messagebox.showwarning("No Data", "⚠️ Please load a log file first!")
            return
        
        # Reset counters
        self.failed_attempts.clear()
        self.total_logins = 0
        self.failed_logins = 0
        suspicious_ips = []
        
        # Clear previous alerts
        self.alert_display.delete(1.0, tk.END)
        
        # Analyze each log entry
        for line in self.log_data:
            log_entry = self.parse_log_line(line)
            
            if log_entry:
                self.total_logins += 1
                
                # Check for failed login attempts
                if log_entry['status'] == 'LOGIN_FAILED':
                    self.failed_logins += 1
                    self.failed_attempts[log_entry['ip']] += 1
        
        # Detect suspicious IPs (3+ failed attempts = threshold)
        FAILED_LOGIN_THRESHOLD = 3
        
        for ip, count in self.failed_attempts.items():
            if count >= FAILED_LOGIN_THRESHOLD:
                suspicious_ips.append((ip, count))
        
        # Display alerts
        self.display_alerts(suspicious_ips)
        
        # Update statistics
        success_logins = self.total_logins - self.failed_logins
        success_rate = (success_logins / self.total_logins * 100) if self.total_logins > 0 else 0
        
        stats_text = f"""📊 ANALYSIS COMPLETE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Login Attempts:     {self.total_logins}
Successful Logins:        {success_logins}
Failed Logins:            {self.failed_logins}
Success Rate:             {success_rate:.1f}%
Suspicious IPs Detected:  {len(suspicious_ips)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        
        self.stats_label.config(text=stats_text)
        
        # Show completion message
        if suspicious_ips:
            messagebox.showwarning(
                "Threats Detected!", 
                f"⚠️ Found {len(suspicious_ips)} suspicious IP(s)!\n\nCheck the Security Alerts panel."
            )
        else:
            messagebox.showinfo(
                "Analysis Complete",
                "✅ No suspicious activity detected!"
            )
    
    def display_alerts(self, suspicious_ips):
        """Display security alerts in the alert panel"""
        if not suspicious_ips:
            self.alert_display.insert(
                tk.END,
                "✅ NO SUSPICIOUS ACTIVITY DETECTED!\n\n"
                "All login attempts appear to be normal.\n"
                "No immediate action required."
            )
            return
        
        # Display critical alerts
        self.alert_display.insert(
            tk.END,
            "⚠️  CRITICAL SECURITY ALERTS DETECTED ⚠️\n"
        )
        self.alert_display.insert(tk.END, "=" * 80 + "\n\n")
        
        for ip, count in sorted(suspicious_ips, key=lambda x: x[1], reverse=True):
            # Determine severity level
            if count >= 5:
                severity = "🔴 HIGH THREAT"
            else:
                severity = "🟡 MEDIUM THREAT"
            
            alert_text = f"{severity}\n"
            alert_text += f"  IP Address:       {ip}\n"
            alert_text += f"  Failed Attempts:  {count}\n"
            alert_text += f"  Recommendation:   Block IP immediately and investigate source\n"
            alert_text += "-" * 80 + "\n\n"
            
            self.alert_display.insert(tk.END, alert_text)
        
        self.alert_display.insert(
            tk.END,
            "=" * 80 + "\n"
            "🔒 ACTION REQUIRED: Review and respond to these threats immediately!\n"
            "   Consider updating firewall rules and notifying security team."
        )
    
    def clear_all(self):
        """Clear all data and reset the application"""
        self.log_data = []
        self.failed_attempts.clear()
        self.total_logins = 0
        self.failed_logins = 0
        
        self.log_display.delete(1.0, tk.END)
        self.alert_display.delete(1.0, tk.END)
        self.stats_label.config(text="📊 Statistics: No logs loaded")
        self.analyze_btn.config(state=tk.DISABLED, bg="#95a5a6")
        
        messagebox.showinfo("Cleared", "✅ All data has been cleared!")

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityLogAnalyzer(root)
    root.mainloop()