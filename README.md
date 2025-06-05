# 📡 Communication_LTD Web System – Vulnerable & Secure Versions

This is a demo project to showcase a web application vulnerable to **SQL Injection** and **Stored XSS**, and how these vulnerabilities can be mitigated in a secure version.

---

## 🚀 How to Run the Project

### 1. Install SQL Server
Download and install **SQL Server** and **SQL Server Management Studio (SSMS)**:
- [Download SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
- [Download SSMS](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms)

---

### 2. Create the Database

Open **SSMS**, click on **New Query**, and run the following script:

```sql
CREATE DATABASE Communication_LTD;
GO

USE Communication_LTD;
GO

CREATE TABLE users (
    id INT PRIMARY KEY IDENTITY,
    username NVARCHAR(100) UNIQUE,
    email NVARCHAR(100),
    salt NVARCHAR(64),
    password NVARCHAR(256)
);

CREATE TABLE clients (
    id INT PRIMARY KEY IDENTITY,
    name NVARCHAR(100)
);
```

---

### 3. Set Your Server Name in `main.py`

Edit the `conn_str` in `main.py` to match your local server. For example:

```python
conn_str = (
    r"DRIVER={ODBC Driver 17 for SQL Server};"
    r"SERVER=(LocalDB)\MSSQLLocalDB;"  # <-- Update this line if needed
    r"DATABASE=Communication_LTD;"
    r"Trusted_Connection=yes;"
)
```

You can find your actual server name in SSMS when connecting.

---

### 4. Install Python Dependencies

Open a terminal (or the terminal inside your IDE), and run:

```bash
pip install flask pyodbc
```

---

### 5. Run the Application

In the terminal:

```bash
python main.py
```

Then open your browser and go to:  
`http://127.0.0.1:5000/`

---

## ✅ Demonstrated Vulnerabilities

- **SQL Injection (SQLi)**: Login is vulnerable if you enter:
  ```
  ' OR '1'='1
  ```
  in the username and password field.

- **Stored XSS**: Adding a client name like:
  ```html
  <script>alert("Hacked!")</script>
  ```
  will cause JavaScript execution on the dashboard.

---
