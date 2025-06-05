from flask import Flask, render_template, request, redirect, url_for, session
import hashlib
from db_connect import DatabaseManager

app = Flask(__name__, static_folder='static')

# Secret key for session management
app.secret_key = 'aP1$kx92@XrD#!w3zTq8*YmG&4vJx7N'


@app.route('/')
def base():
    """Serve the base.html template."""
    return render_template('base.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        # Collect form data
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password using SHA256 for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Create a database connection
        db_manager = DatabaseManager()
        
        # Query the database for the user by username and hashed password
        query = "SELECT id, username, role, avatar_path, password FROM users WHERE username = %s"
        user = db_manager.fetch_one(query, (username,))
        
        db_manager.close_connection()

        # Validate the password
        if user and user['password'] == hashed_password:
            # Store the user's information in the session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['avatar_path'] = user['avatar_path']

            # Redirect to the dashboard if successful
            # Redirect to the dashboard if successful
            # Redirect based on role
            if user['role'] == "admin":
              return redirect(url_for('dashboard', view='dashboard'))
            elif user['role'] == "officer":
              return redirect(url_for('dashboard', view='officer_dashboard'))
            elif user['role'] == "constable":
               return redirect(url_for('dashboard', view='officer_dashboard'))
            else:
               return render_template('errors/404.html'), 404  # âœ… Redirect to custom 404 page
        else:
            # Reload login page with error message
            return render_template('login.html', error="Invalid username or password.")
    else:
        # Serve the login.html template for GET requests
        return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """Serve the dashboard.html template."""
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    db_manager = DatabaseManager()

    # Fetch user details based on session user_id
    query = "SELECT username, role, avatar_path FROM users WHERE id = %s"
    user = db_manager.fetch_one(query, (session['user_id'],))

    db_manager.close_connection()

    # Pass the user object to the template
    return render_template(
        'dashboard.html',
        user=user,
        view='cards'
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    