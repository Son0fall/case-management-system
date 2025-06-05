from flask import Flask, render_template, request, redirect, url_for
import hashlib
from db_connect import DatabaseManager

app = Flask(__name__, static_folder='static')

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        # Collect form data
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        avatar_path = request.form['avatar_path']

        # Hash the password using SHA256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            # Connect to the database
            db_manager = DatabaseManager()

            # Insert the user data into the database
            query = "INSERT INTO users (username, password, role, avatar_path) VALUES (%s, %s, %s, %s)"
            db_manager.execute_query(query, (username, hashed_password, role, avatar_path))
            
            db_manager.close_connection()

            # Success message
            return render_template('create_account.html', success="Account created successfully!")
        except Exception as e:
            # Error message
            return render_template('create_account.html', error=f"Error creating account: {str(e)}")
    else:
        # Serve the create_account.html template for GET requests
        return render_template('create_account.html')

if __name__ == "__main__":
    app.run(debug=True)