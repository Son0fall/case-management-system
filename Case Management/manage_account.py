from flask import Flask, render_template, request, redirect, url_for, session
from db_connect import DatabaseManager
import hashlib  # Import hashlib for password hashing

app = Flask(__name__)
app.secret_key = 'aP1$kx92@XrD#!w3zTq8*YmG&4vJx7N'  # Secure session handling


@app.route('/dashboard')
def dashboard():
    """Dashboard route to render the dashboard with cards or manage account."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    view = request.args.get('view', 'cards')  # Default view is 'cards'
    db_manager = DatabaseManager()

    if view == 'manage_account':
        # Fetch user details for "Manage My Account"
        user_id = session['user_id']
        query = "SELECT username, role, password FROM users WHERE id = %s"
        user = db_manager.fetch_one(query, (user_id,))
        db_manager.close_connection()

        # Render the "Manage My Account" view embedded in the dashboard layout
        return render_template('dashboard.html', username=session['username'], view='manage_account', user=user)
    else:
        # Fetch case counts for the dashboard cards
        total_cases_query = "SELECT COUNT(*) AS total_cases FROM cases"
        total_cases = db_manager.fetch_one(total_cases_query)['total_cases']
        db_manager.close_connection()

        # Render the dashboard with cards
        return render_template('dashboard.html', username=session['username'], view='cards', total_cases=total_cases)


@app.route('/manage_account', methods=['POST'])
def manage_account():
    """Handle updating user details with hashed password."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()
    user_id = session['user_id']

    # Collect user input from the form
    username = request.form['username']
    role = request.form['role']
    password = request.form['password']

    # Hash the password using SHA256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Update user details with the hashed password
    query = "UPDATE users SET username = %s, role = %s, password = %s WHERE id = %s"
    db_manager.execute_query(query, (username, role, hashed_password, user_id))
    db_manager.close_connection()

    # Redirect to the dashboard with the updated view
    return redirect(url_for('dashboard', view='manage_account'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        db_manager = DatabaseManager()
        query = "SELECT id, username, role FROM users WHERE username = %s AND password = %s"
        user = db_manager.fetch_one(query, (username, hashed_password))
        db_manager.close_connection()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)