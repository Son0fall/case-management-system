from flask import Flask, render_template, request, redirect, url_for, session
from db_connect import DatabaseManager
import hashlib

app = Flask(__name__)
app.secret_key = 'aP1$kx92@XrD#!w3zTq8*YmG&4vJx7N'  # Secure session handling


@app.route('/dashboard')
def dashboard():
    """Dashboard route with dynamic content."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    view = request.args.get('view', 'cards')  # Default view is 'cards'
    db_manager = DatabaseManager()

    if view == 'view_list':
        # Fetch all users for the "View Users" table
        query = "SELECT id, username, password, role, avatar_path, created_at FROM users"
        users = db_manager.fetch_all(query)
        db_manager.close_connection()

        # Render the "View Users" table embedded in the dashboard
        return render_template('dashboard.html', username=session['username'], view='view_list', users=users)

    elif view == 'manage_account':
        # Render "Manage My Account" (reuse from previous functionality)
        user_id = session['user_id']
        query = "SELECT username, role, password FROM users WHERE id = %s"
        user = db_manager.fetch_one(query, (user_id,))
        db_manager.close_connection()
        return render_template('dashboard.html', username=session['username'], view='manage_account', user=user)
    else:
        # Default dashboard with cards
        total_cases_query = "SELECT COUNT(*) AS total_cases FROM cases"
        total_cases = db_manager.fetch_one(total_cases_query)['total_cases']

        pending_cases_query = "SELECT COUNT(*) AS pending_cases FROM cases WHERE status = 'Pending'"
        pending_cases = db_manager.fetch_one(pending_cases_query)['pending_cases']

        resolved_cases_query = "SELECT COUNT(*) AS resolved_cases FROM cases WHERE status = 'Resolved'"
        resolved_cases = db_manager.fetch_one(resolved_cases_query)['resolved_cases']

        cancelled_cases_query = "SELECT COUNT(*) AS cancelled_cases FROM cases WHERE status = 'Cancelled'"
        cancelled_cases = db_manager.fetch_one(cancelled_cases_query)['cancelled_cases']

        db_manager.close_connection()

        return render_template('dashboard.html', username=session['username'], view='cards', total_cases=total_cases)


@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    """Handle updating a specific user's details."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()

    if request.method == 'POST':
        # Update user details based on form input
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']
        avatar_path = request.form.get('avatar_path', '')

        # Hash the password for security
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        query = "UPDATE users SET username = %s, role = %s, password = %s, avatar_path = %s WHERE id = %s"
        db_manager.execute_query(query, (username, role, hashed_password, avatar_path, user_id))
        db_manager.close_connection()

        return redirect(url_for('dashboard', view='view_list'))

    # Fetch user details for pre-filled form
    query = "SELECT username, role, password, avatar_path FROM users WHERE id = %s"
    user = db_manager.fetch_one(query, (user_id,))
    db_manager.close_connection()

    return render_template('update_user.html', user=user)


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    """Handle deleting a specific user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()
    query = "DELETE FROM users WHERE id = %s"
    db_manager.execute_query(query, (user_id,))
    db_manager.close_connection()

    return redirect(url_for('dashboard', view='view_list'))


if __name__ == "__main__":
    app.run(debug=True)

