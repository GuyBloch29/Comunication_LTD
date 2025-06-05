איך להריץ:

1) להוריד sql server management studio

2) ללחוץ new query

3) להעתיק :

)

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


4) לשים לב שהסרבר בmain מתאים לסרבר במחשב

# Database connection
conn_str = (
    r"DRIVER={ODBC Driver 17 for SQL Server};"
    r"SERVER=(LocalDB)\MSSQLLocalDB;" - השורה הזאת
    r"DATABASE=Communication_LTD;"
    r"Trusted_Connection=yes;"
)

5) להריץ בטרמינל (אפשר בטרמינל של הסביבת עבודה) :
pip install flask
pip install pyodbc

6) להריץ