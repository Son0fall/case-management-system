import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import hashlib
from werkzeug.utils import secure_filename
import win32api
from db_connect import DatabaseManager
from datetime import datetime, timedelta
from celery.schedules import crontab

app = Flask(__name__, static_folder='static')
app.secret_key = 'aP1$kx92@XrD#!w3zTq8*YmG&4vJx7N'  # Required for secure session handling

# Updated folder path
UPLOAD_FOLDER = 'case management/static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route('/')
def base():
    """Serve the base.html template."""
    return render_template('base.html')

@app.route('/create_account')
def create_account():
    """Serve the base.html template."""
    return render_template('create_account.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login and track login events."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('rememberMe')  # Capture "Remember Me" state

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        db_manager = DatabaseManager()

        # Updated query: Check if the "username" input matches either the username or email field.
        user_query = """
            SELECT id, username, role, avatar_path, password 
            FROM users 
            WHERE username = %s OR email = %s
        """
        user = db_manager.fetch_one(user_query, (username, username))

        if user and user['password'] == hashed_password:
            # Set session variables.
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['avatar_path'] = user['avatar_path'].replace("\\", "/") if user['avatar_path'] else None

            if remember_me:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)

            # Get client details.
            ip_address = request.remote_addr
            device_info = request.headers.get('User-Agent')

            # Record login time in user_login.
            login_query = """
                INSERT INTO user_login (user_id, ip_address, device_info, login_date)
                VALUES (%s, %s, %s, NOW())
            """
            db_manager.execute_query(login_query, (user['id'], ip_address, device_info))

            # Record event in event_log for login.
            event_query = """
                INSERT INTO event_log (user_id, event_type, event_description)
                VALUES (%s, %s, %s)
            """
            db_manager.execute_query(
                event_query,
                (user['id'], 'Login', f'User {username} logged in from {ip_address}')
            )

            db_manager.close_connection()
            return redirect(url_for('dashboard', view='cards'))

        db_manager.close_connection()
        return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')

@app.route('/login_face', methods=['POST'])
def login_face():
    """Validates user by detecting facial structure."""
    frame, error_message = capture_face()
    if error_message:
        return jsonify({"error": error_message}), 500

    # Ensure frame has valid data
    if frame is None or np.mean(frame) == 0:  # Check if frame is completely black
        return jsonify({"error": "No valid image captured"}), 500

    # Use Mediapipe to detect faces
    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    face_results = face_detector.process(frame_rgb)

    if not face_results.detections:
        return jsonify({"error": "No face detected"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, face_encoding FROM users")
    users = cursor.fetchall()
    conn.close()

    for user in users:
        try:
            stored_encoding = json.loads(user[3])

            if str(face_results.detections[0]) == stored_encoding:
                return jsonify({
                    "success": True,
                    "username": user[1],
                    "role": user[2],
                    "redirect": url_for('dashboard', view='cards') if user[2] == "admin" else url_for('dashboard', view='officer')
                }), 200
        except ValueError:
            continue

    return jsonify({"error": "Face not recognized"}), 403

@app.route('/dashboard')
def dashboard():
    """Render the dashboard with dynamic views and track user activity."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Determine the view; default to 'cards' if not specified or invalid.
    view = request.args.get('view')
    if not view or view not in ['cards', 'view_list', 'view_cases', 'add_user', 'add_case', 'reports', 'manage_account']:
        view = 'cards'

    db_manager = DatabaseManager()

    # Log the page visit event.
    event_query = """
        INSERT INTO event_log (user_id, event_type, event_description, page_visited)
        VALUES (%s, %s, %s, %s)
    """
    db_manager.execute_query(
        event_query,
        (session['user_id'], 'Visit Page', f'Visited {view} page', view)
    )

    # Fetch user details for display.
    # IMPORTANT: Include the id (and email, if required)
    user_query = "SELECT id, username, role, avatar_path, email FROM users WHERE id = %s"
    user = db_manager.fetch_one(user_query, (session['user_id'],))
    if not user:
        db_manager.close_connection()
        return "Error: User details not fetched from database"

    if user['avatar_path']:
        # Adjust the avatar path so it points appropriately (e.g., to "/static/images")
        user['avatar_path'] = url_for('static', filename=f"images/{user['avatar_path'].split('/')[-1]}")

    if view == 'cards':
        # Get aggregated case counts.
        total_cases_query     = "SELECT COUNT(*) AS total_cases FROM cases"
        pending_cases_query   = "SELECT COUNT(*) AS pending_cases FROM cases WHERE status = 'Pending'"
        resolved_cases_query  = "SELECT COUNT(*) AS resolved_cases FROM cases WHERE status = 'Resolved'"
        cancelled_cases_query = "SELECT COUNT(*) AS cancelled_cases FROM cases WHERE status = 'Cancelled'"

        total_cases     = db_manager.fetch_one(total_cases_query)['total_cases']
        pending_cases   = db_manager.fetch_one(pending_cases_query)['pending_cases']
        resolved_cases  = db_manager.fetch_one(resolved_cases_query)['resolved_cases']
        cancelled_cases = db_manager.fetch_one(cancelled_cases_query)['cancelled_cases']

        db_manager.close_connection()

        return render_template(
            'dashboard.html',
            user=user,
            avatar_path=user['avatar_path'],
            username=user['username'],
            role=user['role'],
            view='cards',
            total_cases=total_cases,
            pending_cases=pending_cases,
            resolved_cases=resolved_cases,
            cancelled_cases=cancelled_cases
        )

    elif view == 'view_list':
        if session['role'] != "admin":
            db_manager.close_connection()
            return render_template('errors/403.html'), 403

        # For admins, get the list of users.
        query = "SELECT id, email, username, role, avatar_path, created_at FROM users"
        users = db_manager.fetch_all(query)

        # Adjust each user's avatar_path.
        for usr in users:
            if usr['avatar_path']:
                usr['avatar_path'] = url_for('static', filename=f"images/{usr['avatar_path'].split('/')[-1]}")
        db_manager.close_connection()

        return render_template('dashboard.html', user=user, view='view_list', users=users)

    elif view == 'view_cases':
        query = """
            SELECT c.id, c.case_number, c.description, c.crime_type, c.status, 
                   u1.username AS created_by, u2.username AS assigned_to, 
                   c.court_date, c.created_at
            FROM cases c
            LEFT JOIN users u1 ON c.created_by = u1.id
            LEFT JOIN users u2 ON c.assigned_to = u2.id
        """
        cases = db_manager.fetch_all(query)
        db_manager.close_connection()
        return render_template('dashboard.html', user=user, view='view_cases', cases=cases)

    elif view == 'add_user':
        if session['role'] != "admin":
            db_manager.close_connection()
            return render_template('errors/403.html'), 403
        db_manager.close_connection()
        return render_template('dashboard.html', user=user, view='add_user')

    elif view == 'add_case':
        users_query = "SELECT id, username FROM users"
        users = db_manager.fetch_all(users_query)
        db_manager.close_connection()
        return render_template('dashboard.html', user=user, view='add_case', users=users)

    elif view == 'reports':
        db_manager.close_connection()
        return render_template('dashboard.html', user=user, view='reports')

    elif view == 'manage_account':
        # Render the Manage Account view for the current user.
        db_manager.close_connection()
        return render_template('dashboard.html', user=user, view='manage_account')

    elif view == 'logout':
        db_manager.close_connection()
        session.clear()
        return redirect(url_for('login'))

    else:
        db_manager.close_connection()
        return render_template('dashboard.html', user=user, view='cards')



# ----------------- Manage Account -----------------------
@app.route('/manage_account', methods=['POST'])
def manage_account():
    """Update user details from the manage account form and track the event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()
    user_id = session['user_id']

    # Collect updated fields from form
    username = request.form.get('username')
    role = request.form.get('role')
    password = request.form.get('password', '')

    # Only update if a new password is provided
    hashed_password = None
    if password.strip():
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Handle optional avatar upload
    avatar_path = None
    if 'avatar_path' in request.files:
        avatar_file = request.files['avatar_path']
        if avatar_file.filename != '':
            filename = secure_filename(avatar_file.filename)
            avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace("\\", "/")
            avatar_file.save(avatar_path)

    # Construct dynamic update query based on provided fields
    update_fields = []
    update_values = []

    if username:
        update_fields.append("username = %s")
        update_values.append(username)
    if role:
        update_fields.append("role = %s")
        update_values.append(role)
    if hashed_password:
        update_fields.append("password = %s")
        update_values.append(hashed_password)
    if avatar_path:
        update_fields.append("avatar_path = %s")
        update_values.append(avatar_path)
    # ----------------- Email Update (Added) -----------------
    if request.form.get('email'):
        email = request.form.get('email')
        update_fields.append("email = %s")
        update_values.append(email)
    # ---------------------------------------------------------

    if update_fields:
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
        update_values.append(user_id)
        db_manager.execute_query(query, tuple(update_values))

        # Log the update account event.
        event_query = """
            INSERT INTO event_log (user_id, event_type, event_description)
            VALUES (%s, %s, %s)
        """
        db_manager.execute_query(event_query,
                                 (user_id, 'Manage Account', f'User {session["username"]} updated account details'))
    else:
        # If no fields were updated, you may log it or do nothing.
        pass

    db_manager.close_connection()
    return redirect(url_for('dashboard', view='manage_account'))


# ----------------- Update User (Admin Task) -----------------------
@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    """Allow only admins to update user details and track event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()

    # Verify that the logged-in user is admin.
    logged_user_query = "SELECT id, email, username, role, avatar_path FROM users WHERE id = %s"
    logged_user = db_manager.fetch_one(logged_user_query, (session['user_id'],))
    if not logged_user or logged_user['role'] != "admin":
        db_manager.close_connection()
        return render_template('errors/403.html', error="Only admins can update users.")

    # Ensure the target user exists.
    user_query = "SELECT password, avatar_path FROM users WHERE id = %s"
    target_user = db_manager.fetch_one(user_query, (user_id,))
    if not target_user:
        db_manager.close_connection()
        return render_template('errors/404.html', error="User not found.")

    # Determine updated password (if provided)
    password = request.form.get('password')
    hashed_password = hashlib.sha256(password.encode()).hexdigest() if password.strip() else target_user['password']

    # Handle avatar upload update
    avatar_path = target_user['avatar_path']
    if 'avatar_path' in request.files and request.files['avatar_path'].filename:
        avatar_file = request.files['avatar_path']
        filename = secure_filename(avatar_file.filename)
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace("\\", "/")
        avatar_file.save(avatar_path)

    # Update email, username, role, password, and avatar
    update_query = """
        UPDATE users 
        SET email = %s, username = %s, role = %s, password = %s, avatar_path = %s
        WHERE id = %s
    """
    db_manager.execute_query(update_query, (
        request.form['email'], request.form['username'], request.form['role'],
        hashed_password, avatar_path, user_id
    ))

    # Log the update user event.
    event_query = """
        INSERT INTO event_log (user_id, event_type, event_description, record_id)
        VALUES (%s, %s, %s, %s)
    """
    db_manager.execute_query(event_query,
                             (session['user_id'], 'Update User', f'Updated details for user id {user_id}', user_id))

    db_manager.close_connection()
    return redirect(url_for('dashboard', view='view_list'))


# ----------------- Delete User (Admin Task) -----------------------
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    """Delete a specific user and track the event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] != "admin":
        return render_template('errors/403.html'), 403

    db_manager = DatabaseManager()
    delete_query = "DELETE FROM users WHERE id = %s"
    db_manager.execute_query(delete_query, (user_id,))

    # Log delete event.
    event_query = """
        INSERT INTO event_log (user_id, event_type, event_description, record_id)
        VALUES (%s, %s, %s, %s)
    """
    db_manager.execute_query(event_query,
                             (session['user_id'], 'Delete User', f'Deleted user with id {user_id}', user_id))

    db_manager.close_connection()
    return redirect(url_for('dashboard', view='view_list'))


@app.route('/add_user', methods=['POST'])
def add_user():
    """Handle the Add User form submission and track the event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] != "admin":
        return render_template('errors/403.html', error="Only admins can add new users."), 403

    db_manager = DatabaseManager()
    try:
        # Preserve the current session's user id (the creator)
        created_by = session['user_id']

        # Collect form data
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        role = request.form['role']
        avatar_path = None

        if 'avatar_path' in request.files:
            avatar_file = request.files['avatar_path']
            if avatar_file.filename != '':
                filename = secure_filename(avatar_file.filename)
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace("\\", "/")
                avatar_file.save(avatar_path)

        # Insert the new user record (note: do NOT change the current session)
        query = "INSERT INTO users (email, username, password, role, avatar_path) VALUES (%s, %s, %s, %s, %s)"
        db_manager.execute_query(query, (email, username, hashed_password, role, avatar_path))

        # Log add user event
        event_query = """
            INSERT INTO event_log (user_id, event_type, event_description)
            VALUES (%s, %s, %s)
        """
        db_manager.execute_query(
            event_query,
            (session['user_id'], 'Add User', f'Added user {username} with email {email}')
        )
        db_manager.close_connection()
        return redirect(url_for('dashboard'))
    except Exception as e:
        db_manager.close_connection()
        return render_template('errors/500.html', error=str(e)), 500

# ----------------- Update Case -----------------------
@app.route('/update_case/<int:case_id>', methods=['GET', 'POST'])
def update_case(case_id):
    """Update case details and track the event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] not in ["officer", "constable", "admin"]:
        return render_template('errors/403.html'), 403

    db_manager = DatabaseManager()

    # Fetch logged-in user details.
    user_query = "SELECT id, username, role, avatar_path FROM users WHERE id = %s"
    user = db_manager.fetch_one(user_query, (session['user_id'],))
    if not user:
        db_manager.close_connection()
        return render_template('errors/404.html', error="User not found.")

    if user['avatar_path']:
        user['avatar_path'] = url_for('static', filename=f"images/{user['avatar_path'].split('/')[-1]}")

    if request.method == 'POST':
        # Collect updated case details
        case_number = request.form['case_number']
        description = request.form['description']
        status = request.form['status']
        created_by = request.form['created_by']
        assigned_to = request.form['assigned_to']
        court_date = request.form['court_date']
        # NEW: Collect the crime type value from the form.
        crime_type = request.form['crime_type']

        update_query = """
            UPDATE cases 
            SET case_number = %s, description = %s, status = %s, 
                created_by = %s, assigned_to = %s, court_date = %s, crime_type = %s
            WHERE id = %s
        """
        db_manager.execute_query(update_query,
                                 (case_number, description, status, created_by, assigned_to, court_date, crime_type, case_id))

        # Log the update case event.
        event_query = """
            INSERT INTO event_log (user_id, event_type, event_description, record_id)
            VALUES (%s, %s, %s, %s)
        """
        db_manager.execute_query(
            event_query,
            (session['user_id'], 'Update Case', f'Updated case with id {case_id}', case_id)
        )

        db_manager.close_connection()
        return redirect(url_for('dashboard', view='view_cases'))

    else:
        # GET: Fetch case details for form prepopulation.
        case_query = """
            SELECT c.id, c.case_number, c.description, c.status, 
                   u1.username AS created_by, u2.username AS assigned_to, 
                   c.court_date, c.created_at, c.crime_type
            FROM cases c
            LEFT JOIN users u1 ON c.created_by = u1.id
            LEFT JOIN users u2 ON c.assigned_to = u2.id
            WHERE c.id = %s
        """
        case = db_manager.fetch_one(case_query, (case_id,))

        users_query = "SELECT id, username FROM users"
        users = db_manager.fetch_all(users_query)

        db_manager.close_connection()
        if not case:
            return render_template('errors/404.html', error="Case not found.")
        return render_template('dashboard.html', view='update_case', case=case, users=users, user=user)

@app.route('/add_case', methods=['POST'])
def add_case():
    """Handle the Add Case form submission and track the event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] not in ["officer", "constable", "admin"]:
        return render_template('errors/403.html', error="You are not authorized to add cases."), 403

    db_manager = DatabaseManager()
    try:
        # Collect form data for the case
        case_number = request.form['case_number']
        description = request.form['description']
        status = request.form['status']
        created_by = request.form['created_by']
        assigned_to = request.form['assigned_to']
        court_date = request.form['court_date']
        # NEW: Collect the crime type in the Add Case form.
        crime_type = request.form['crime_type']

        query = """
            INSERT INTO cases (case_number, description, status, created_by, assigned_to, court_date, crime_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        db_manager.execute_query(query, (case_number, description, status, created_by, assigned_to, court_date, crime_type))

        # Log add case event
        event_query = """
            INSERT INTO event_log (user_id, event_type, event_description)
            VALUES (%s, %s, %s)
        """
        db_manager.execute_query(
            event_query,
            (session['user_id'], 'Add Case', f'Added case {case_number}')
        )
        db_manager.close_connection()
        return redirect(url_for('dashboard', view='view_cases'))
    except Exception as e:
        db_manager.close_connection()
        return render_template('errors/500.html', error=str(e)), 500


@app.route('/delete_case/<int:case_id>')
def delete_case(case_id):
    """Handle deleting a specific case and track the event."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] != "admin":
        return render_template('errors/403.html', error="Only admins can delete cases."), 403

    db_manager = DatabaseManager()
    try:
        # Delete the case
        query = "DELETE FROM cases WHERE id = %s"
        db_manager.execute_query(query, (case_id,))

        # Log deletion event
        event_query = """
            INSERT INTO event_log (user_id, event_type, event_description, record_id)
            VALUES (%s, %s, %s, %s)
        """
        db_manager.execute_query(
            event_query,
            (session['user_id'], 'Delete Case', f'Case with id {case_id} deleted', case_id)
        )
        db_manager.close_connection()
        return redirect(url_for('dashboard', view='view_cases'))

    except Exception as e:
        db_manager.close_connection()
        return render_template('errors/500.html', error=str(e)), 500


@app.route('/reports')
def reports():
    """Generate police case reports, graphs, and a detailed event log for the current user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] != "admin":
        return render_template('errors/403.html', error="Only admins can view the reports log."), 403

    db_manager = DatabaseManager()
    try:
        # Fetch logged-in user details
        user_query = "SELECT id, username, role, avatar_path FROM users WHERE id = %s"
        user = db_manager.fetch_one(user_query, (session['user_id'],))
        if not user:
            db_manager.close_connection()
            return render_template('errors/404.html', error="User details not found in the database")

        # Format avatar path
        user['avatar_path'] = (url_for('static', filename=f"images/{user['avatar_path'].split('/')[-1]}")
                               if user['avatar_path'] else None)

        # Case status summary (for table and pie chart)
        case_status_query = "SELECT status, COUNT(*) AS total FROM cases GROUP BY status"
        case_status = db_manager.fetch_all(case_status_query)

        # Crime Analysis
        crime_query = "SELECT crime_type, frequency FROM crime_analysis ORDER BY frequency DESC"
        crime_stats = db_manager.fetch_all(crime_query)
        # Fallback snippet: if no crime data is found, set a default value.
        if not crime_stats:
            crime_stats = [{'crime_type': 'No Crime Data', 'frequency': 0}]

        # Officer Activity
        officer_query = "SELECT u.username, o.cases_handled FROM officer_activity o JOIN users u ON o.officer_id = u.id"
        officer_activity = db_manager.fetch_all(officer_query)

        # Arrest Reports
        arrest_query = "SELECT suspect_name, outcome, arrest_date FROM arrests ORDER BY arrest_date DESC"
        arrest_records = db_manager.fetch_all(arrest_query)

        # Upcoming Court Dates
        court_query = """
            SELECT c.case_number, cd.court_date, cd.judge 
            FROM court_dates cd JOIN cases c ON cd.case_id = c.id 
            ORDER BY cd.court_date ASC
        """
        court_schedules = db_manager.fetch_all(court_query)

        # Event Log Summary (for overall system events – pie chart)
        event_summary_query = "SELECT event_type, COUNT(*) AS total FROM event_log GROUP BY event_type"
        event_summary = db_manager.fetch_all(event_summary_query)

        # Detailed Event Log for the current user (sorted by most recent events)
        user_events_query = """
            SELECT event_id, event_type, event_description, event_date 
            FROM event_log WHERE user_id = %s ORDER BY event_date DESC
        """
        user_events = db_manager.fetch_all(user_events_query, (user['id'],))

        db_manager.close_connection()

        return render_template(
            'dashboard.html',
            view='reports',
            user=user,
            case_status=case_status,
            crime_stats=crime_stats,
            officer_activity=officer_activity,
            arrest_records=arrest_records,
            court_schedules=court_schedules,
            event_summary=event_summary,
            user_events=user_events
        )
    except Exception as e:
        db_manager.close_connection()
        return render_template('errors/500.html', error=str(e)), 500



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset requests, track event log, and render error if not found."""
    if request.method == 'POST':
        email = request.form['email']
        db_manager = DatabaseManager()
        try:
            user_query = "SELECT id FROM users WHERE email = %s"
            user = db_manager.fetch_one(user_query, (email,))
            if user:
                session['reset_user_id'] = user['id']
                # Log forgot password event
                event_query = """
                    INSERT INTO event_log (user_id, event_type, event_description)
                    VALUES (%s, %s, %s)
                """
                db_manager.execute_query(
                    event_query,
                    (user['id'], 'Forgot Password Request', f'User requested password reset for email {email}')
                )
                db_manager.close_connection()
                return redirect(url_for('reset_password'))
            else:
                db_manager.close_connection()
                return render_template('forgot_password.html', error="Email not found.")
        except Exception as e:
            db_manager.close_connection()
            return render_template('errors/500.html', error=str(e)), 500

    return render_template('forgot-password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Allow users to reset their password, track event log, and render error if mismatch."""
    if 'reset_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return render_template('reset_password.html', error="Passwords do not match.")

        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        db_manager = DatabaseManager()
        try:
            update_query = "UPDATE users SET password = %s WHERE id = %s"
            db_manager.execute_query(update_query, (hashed_password, session['reset_user_id']))

            # Log password reset event
            event_query = """
                INSERT INTO event_log (user_id, event_type, event_description)
                VALUES (%s, %s, %s)
            """
            db_manager.execute_query(
                event_query,
                (session['reset_user_id'], 'Password Reset', 'User successfully updated their password')
            )
            db_manager.close_connection()
            session.pop('reset_user_id')  # Remove reset session after update
            return redirect(url_for('login'))
        except Exception as e:
            db_manager.close_connection()
            return render_template('errors/500.html', error=str(e)), 500

    return render_template('re-new-password.html')


# ----------------- Get Event Details -----------------
@app.route('/get_event_details', methods=['GET'])
def get_event_details():
    """Fetch full event details when clicking the eye button."""
    event_id = request.args.get('event_id')
    if not event_id:
        return jsonify({"error": "Event ID is missing"}), 400

    db_manager = DatabaseManager()
    event_query = """
        SELECT u.username, e.event_type, e.event_description, e.page_visited, e.event_date 
        FROM event_log e 
        JOIN users u ON e.user_id = u.id 
        WHERE e.event_id = %s
    """
    event = db_manager.fetch_one(event_query, (event_id,))
    db_manager.close_connection()

    if not event:
        return jsonify({"error": "Event not found"}), 404

    print("Fetched event:", event)  # Debugging: check if event exists
    return jsonify(event)


# ----------------- Error Handlers -----------------
@app.errorhandler(404)
def not_found_error(error):
    """Handles 404 Not Found error."""
    return render_template('errors/404.html'), 404


@app.errorhandler(403)
def forbidden_error(error):
    """Handles 403 Forbidden error."""
    return render_template('errors/403.html'), 403


@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 Internal Server Error."""
    return render_template('errors/500.html'), 500


@app.errorhandler(503)
def service_unavailable_error(error):
    """Handles 503 Service Unavailable error."""
    return render_template('errors/503.html'), 503


CELERY_BEAT_SCHEDULE = {
    'check-and-insert-arrests-every-hour': {
        'task': 'tasks.check_and_insert_arrests',
        'schedule': crontab(minute=0, hour='*'),
    },
}

# ----------------- Logout Route -----------------
@app.route('/logout')
def logout():
    """Log logout events, update user_login with logout time, and clear session."""
    if 'user_id' in session:
        user_id = session['user_id']
        db_manager = DatabaseManager()

        # Update the logout_date for the latest login record for this user
        logout_query = """
            UPDATE user_login 
            SET logout_date = NOW() 
            WHERE user_id = %s 
            ORDER BY login_date DESC 
            LIMIT 1
        """
        db_manager.execute_query(logout_query, (user_id,))

        # Record logout event in event_log
        event_query = """
            INSERT INTO event_log (user_id, event_type, event_description)
            VALUES (%s, %s, %s)
        """
        db_manager.execute_query(
            event_query,
            (user_id, 'Logout', f'User {session["username"]} logged out')
        )

        db_manager.close_connection()

    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
