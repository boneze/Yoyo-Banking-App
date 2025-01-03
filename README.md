# Yoyo-Banking-App
Fintech app creation
import tkinter as tk
from tkinter import messagebox
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import base64
from cryptography.fernet import Fernet

class YoyoBankingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Yoyo Banking App")
        self.root.geometry("600x800")
        self.root.configure(bg="#f0f0f0")

        # Generate or load encryption key
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

        self.balance = 0  # Initial balance
        self.savings = 0
        self.investments = 0

        # Login Page
        self.login_page()

    def login_page(self):
        self.clear_root()
        tk.Label(self.root, text="Login to Yoyo Bank", font=("Helvetica", 18, "bold"), pady=10, bg="#004aad", fg="white").pack(fill=tk.X)

        login_frame = tk.Frame(self.root, bg="#f0f0f0")
        login_frame.pack(pady=50)

        tk.Label(login_frame, text="Username:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(login_frame, font=("Helvetica", 12), width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(login_frame, text="Password:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(login_frame, font=("Helvetica", 12), width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(login_frame, text="Login", font=("Helvetica", 12), command=self.validate_login, bg="#28a745", fg="white").grid(row=2, column=0, columnspan=2, pady=10)

        # Additional Authentication Options
        tk.Label(self.root, text="Or sign in using:", font=("Helvetica", 12), pady=10, bg="#f0f0f0").pack()
        auth_frame = tk.Frame(self.root, bg="#f0f0f0")
        auth_frame.pack(pady=10)

        tk.Button(auth_frame, text="2FA", font=("Helvetica", 12), command=self.two_factor_auth, bg="#007bff", fg="white").grid(row=0, column=0, padx=10, pady=5)
        tk.Button(auth_frame, text="Biometrics", font=("Helvetica", 12), command=self.biometrics_auth, bg="#007bff", fg="white").grid(row=0, column=1, padx=10, pady=5)
        tk.Button(auth_frame, text="Facial Recognition", font=("Helvetica", 12), command=self.facial_recognition_auth, bg="#007bff", fg="white").grid(row=0, column=2, padx=10, pady=5)
        tk.Button(auth_frame, text="PIN Code", font=("Helvetica", 12), command=self.pin_code_auth, bg="#007bff", fg="white").grid(row=0, column=3, padx=10, pady=5)

    def validate_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == "admin" and password == "password":  # Example credentials
            self.main_page()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def two_factor_auth(self):
        messagebox.showinfo("2FA", "Two-Factor Authentication is not implemented yet.")

    def biometrics_auth(self):
        messagebox.showinfo("Biometrics", "Biometric Authentication is not implemented yet.")

    def facial_recognition_auth(self):
        messagebox.showinfo("Facial Recognition", "Facial Recognition Authentication is not implemented yet.")

    def pin_code_auth(self):
        messagebox.showinfo("PIN Code", "PIN Code Authentication is not implemented yet.")

    def main_page(self):
        self.clear_root()

        # Header
        header = tk.Label(self.root, text="Welcome to Yoyo Bank", font=("Helvetica", 18, "bold"), pady=10, bg="#004aad", fg="white")
        header.pack(fill=tk.X)

        # Balance Display
        self.balance_label = tk.Label(self.root, text=f"Balance: $ {self.balance}", font=("Helvetica", 14), pady=10, bg="#f0f0f0")
        self.balance_label.pack()

        # Deposit Section
        deposit_frame = tk.Frame(self.root, bg="#f0f0f0")
        deposit_frame.pack(pady=10)
        tk.Label(deposit_frame, text="Deposit Amount:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5)
        self.deposit_entry = tk.Entry(deposit_frame, font=("Helvetica", 12), width=20)
        self.deposit_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(deposit_frame, text="Deposit", font=("Helvetica", 12), command=self.deposit, bg="#28a745", fg="white").grid(row=0, column=2, padx=5, pady=5)

        # Withdraw Section
        withdraw_frame = tk.Frame(self.root, bg="#f0f0f0")
        withdraw_frame.pack(pady=10)
        tk.Label(withdraw_frame, text="Withdraw Amount:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5)
        self.withdraw_entry = tk.Entry(withdraw_frame, font=("Helvetica", 12), width=20)
        self.withdraw_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(withdraw_frame, text="Withdraw", font=("Helvetica", 12), command=self.withdraw, bg="#dc3545", fg="white").grid(row=0, column=2, padx=5, pady=5)

        # Transfer Section
        transfer_frame = tk.Frame(self.root, bg="#f0f0f0")
        transfer_frame.pack(pady=10)
        tk.Label(transfer_frame, text="Recipient Account:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5)
        self.recipient_entry = tk.Entry(transfer_frame, font=("Helvetica", 12), width=20)
        self.recipient_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(transfer_frame, text="Transfer Amount:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5)
        self.transfer_amount_entry = tk.Entry(transfer_frame, font=("Helvetica", 12), width=20)
        self.transfer_amount_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(transfer_frame, text="Transfer", font=("Helvetica", 12), command=self.transfer, bg="#007bff", fg="white").grid(row=2, column=0, columnspan=2, pady=10)

        # Transaction History Section
        tk.Label(self.root, text="Transaction History:", font=("Helvetica", 12, "bold"), pady=10, bg="#f0f0f0").pack()
        history_frame = tk.Frame(self.root, bg="#f0f0f0")
        history_frame.pack(pady=5)
        self.transaction_history = tk.Text(history_frame, height=10, width=50, state=tk.DISABLED, wrap=tk.WORD, font=("Helvetica", 10), bg="#ffffff", relief=tk.GROOVE, borderwidth=2)
        self.transaction_history.pack(padx=5, pady=5)

        # Graphical Analysis Section
        tk.Label(self.root, text="Savings and Investment Analysis:", font=("Helvetica", 12, "bold"), pady=10, bg="#f0f0f0").pack()
        self.create_analysis_chart()

    def create_analysis_chart(self):
        self.figure = Figure(figsize=(5, 3), dpi=100)
        self.axis = self.figure.add_subplot(111)
        self.update_chart()
        
        chart = FigureCanvasTkAgg(self.figure, self.root)
        chart.get_tk_widget().pack(pady=10)

    def update_chart(self):
        labels = ['Savings', 'Investments']
        values = [self.savings, self.investments]
        self.axis.clear()
        self.axis.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, colors=['#007bff', '#28a745'])
        self.axis.set_title("Portfolio Distribution")

    def encrypt_data(self, data):
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    def deposit(self):
        try:
            amount = float(self.deposit_entry.get())
            if amount <= 0:
                raise ValueError("Amount must be positive.")
            self.balance += amount
            self.savings += amount * 0.8  # Allocate 80% to savings
            self.investments += amount * 0.2  # Allocate 20% to investments
            self.update_balance()
            self.update_chart()
            transaction = f"Deposited: $ {amount}"
            self.add_transaction(transaction)
            self.deposit_entry.delete(0, tk.END)
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))

    def withdraw(self):
        try:
            amount = float(self.withdraw_entry.get())
            if amount <= 0:
                raise ValueError("Amount must be
                from urllib.parse import urlunparse, urlencode

# Components of the URL
scheme = 'https'
netloc = 'api.yoyobank.com'
path = '/transfer'
params = ''
query = {
    'user_id': '12345',
    'recipient_id': '67890',
    'amount': '100',
    'currency': 'USD',
    'token': 'secure_transaction_token'
}
fragment = ''

# Build the query string
query_string = urlencode(query)

# Create the URL
url = urlunparse((scheme, netloc, path, params, query_string, fragment))

print("Generated URL for Transfer:", url)

