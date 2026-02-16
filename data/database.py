import psycopg2

# Configuration
DB_NAME = "integridos"
DB_USER = "st11"
DB_PASSWORD = "st11_2026"
DB_HOST = "localhost"
DB_PORT = 5432

try: 
    # Connect to the PostgreSQL database
    connection = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    print("Database connection established successfully.")
except Exception as e:
    print(f"Error connecting to the database: {e}")
    connection = None

if connection:
    connection.close()