import mysql.connector
from flask import Flask

# Database Manager Class
class DatabaseManager:
    def __init__(self, host="localhost", user="root", password="", database="police_case_management"):
        try:
            self.connection = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )
            self.cursor = self.connection.cursor(dictionary=True)
            print("Database connected successfully!")
        except mysql.connector.Error as e:
            print(f"Error connecting to database: {e}")
            self.connection = None
            self.cursor = None

    def execute_query(self, query, params=None):
        if self.connection:
            self.cursor.execute(query, params or ())
            self.connection.commit()
        else:
            raise Exception("No database connection.")

    def fetch_one(self, query, params=None):
        if self.connection:
            self.cursor.execute(query, params or ())
            return self.cursor.fetchone()
        else:
            raise Exception("No database connection.")

    def fetch_all(self, query, params=None):
        if self.connection:
            self.cursor.execute(query, params or ())
            return self.cursor.fetchall()
        else:
            raise Exception("No database connection.")

    def close_connection(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()

# Flask App for Testing
app = Flask(__name__)

@app.route('/')
def test_db_connection():
    try:
        # Create a DatabaseManager instance to test the connection
        db_manager = DatabaseManager()
        if db_manager.connection:
            # Test query execution
            db_manager.execute_query("SELECT 1")
            db_manager.close_connection()
            return "<h1>Database Connected Successfully!</h1>"
        else:
            return "<h1>Error: Unable to Connect to Database.</h1>"
    except Exception as e:
        return f"<h1>Error: {str(e)}</h1>"

if __name__ == "__main__":
    app.run(debug=True)