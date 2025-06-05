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

    # List Cases From Database #
    if view == 'view_cases':
        # Fetch all cases for the "View Cases" table
        query = "SELECT id,case_number,description,status,created_by,assigned_to,court_date,created_at FROM cases"
        users = db_manager.fetch_all(query)
        db_manager.close_connection()

        # Render the "View Cases" table embedded in the dashboard
        return render_template('dashboard.html', username=session['username'], view='view_cases', users=users)

    elif view == 'manage_cases':
        # Render "Manage My Account" (reuse from previous functionality)
        case_id = session['case_id']
        query = "SELECT case_number, description, status, created_by, assigned_to, court_date, created_at FROM cases WHERE id = %s"
        case = db_manager.fetch_one(query, (case_id,))
        db_manager.close_connection()
        return render_template('dashboard.html', username=session['username'], view='manage_cases', case=case)
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


@app.route('/update_case/<int:case_id>', methods=['GET', 'POST'])
def update_user(case_id):
    """Handle updating a specific case's details."""
    if 'case_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()

    if request.method == 'POST':
        # Update case details based on form input
        case_number = request.form['case_number']
        description = request.form['description']
        status = request.form['status']
        created_by = request.form['created_by']
        assigned_to = request.form['assigned_to']
        court_date = request.form['court_date']
        created_at = request.form['created_at']

        query = "UPDATE cases SET case_number = %s, description = %s, status = %s, created_by = %s, assigned_to = %s, court_date = %s, created_at = %s WHERE id = %s"
        db_manager.execute_query(query, (case_number, description, status, created_by, assigned_to, court_date, created_at, case_id))
        db_manager.close_connection()

        return redirect(url_for('dashboard', view='view_cases'))

    # Fetch user details for pre-filled form
    query = "SELECT case_number, description, status, created_by, assigned_to, court_date, created_at FROM cases WHERE id = %s"
    case = db_manager.fetch_one(query, (case_id,))
    db_manager.close_connection()

    return render_template('update_cases.html', case=case)


@app.route('/delete_case/<int:case_id>')
def delete_user(case_id):
    """Handle deleting a specific case."""
    if 'case_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()
    query = "DELETE FROM cases WHERE id = %s"
    db_manager.execute_query(query, (case_id,))
    db_manager.close_connection()

    return redirect(url_for('dashboard', view='view_cases'))


if __name__ == "__main__":
    app.run(debug=True)
