//dashboard.py
from flask import Flask, render_template, request, redirect, url_for, session
import hashlib
from db_connect import DatabaseManager
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'aP1$kx92@XrD#!w3zTq8*YmG&4vJx7N'  # Required for secure session handling


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Collect login credentials
        username = request.form['username']
        password = request.form['password']

        # Hash the password using SHA256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            # Connect to the database
            db_manager = DatabaseManager()

            # Query the database for the user
            query = "SELECT id, username, role FROM users WHERE username = %s AND password = %s"
            user = db_manager.fetch_one(query, (username, hashed_password))

            if user:
                # Store user details in the session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']

                db_manager.close_connection()
                return redirect(url_for('dashboard', view='cards'))
            else:
                db_manager.close_connection()
                return render_template('login.html', error="Invalid username or password.")
        except Exception as e:
            return render_template('login.html', error=f"Error during login: {str(e)}")
    else:
        return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """Render the dashboard with dynamic views."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    view = request.args.get('view', 'cards')  # Default view is 'cards'
    db_manager = DatabaseManager()

    if view == 'cards':
        # Fetch case counts
        total_cases_query = "SELECT COUNT(*) AS total_cases FROM cases"
        total_cases = db_manager.fetch_one(total_cases_query)['total_cases']

        pending_cases_query = "SELECT COUNT(*) AS pending_cases FROM cases WHERE status = 'Pending'"
        pending_cases = db_manager.fetch_one(pending_cases_query)['pending_cases']

        resolved_cases_query = "SELECT COUNT(*) AS resolved_cases FROM cases WHERE status = 'Resolved'"
        resolved_cases = db_manager.fetch_one(resolved_cases_query)['resolved_cases']

        cancelled_cases_query = "SELECT COUNT(*) AS cancelled_cases FROM cases WHERE status = 'Cancelled'"
        cancelled_cases = db_manager.fetch_one(cancelled_cases_query)['cancelled_cases']

        db_manager.close_connection()

        return render_template(
            'dashboard.html',
            username=session['username'],
            view='cards',
            total_cases=total_cases,
            pending_cases=pending_cases,
            resolved_cases=resolved_cases,
            cancelled_cases=cancelled_cases
        )
    elif view == 'manage_account':
        # Manage account view
        user_id = session['user_id']
        query = "SELECT username, role, avatar_path FROM users WHERE id = %s"
        user = db_manager.fetch_one(query, (user_id,))
        db_manager.close_connection()

        return render_template('dashboard.html', username=session['username'], view='manage_account', user=user)
    elif view == 'view_list':
        # Fetch all users
        query = "SELECT id, username, password, role, avatar_path, created_at FROM users"
        users = db_manager.fetch_all(query)
        db_manager.close_connection()

        return render_template('dashboard.html', username=session['username'], view='view_list', users=users)


@app.route('/manage_account', methods=['POST'])
def manage_account():
    """Update user details from the manage account form."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()
    user_id = session['user_id']

    # Update user details
    username = request.form['username']
    role = request.form['role']
    avatar_path = request.form.get('avatar_path', '')
    query = "UPDATE users SET avatar_path = %s, username = %s, role = %s WHERE id = %s"
    db_manager.execute_query(query, (avatar_path, username, role, user_id))
    db_manager.close_connection()

    return redirect(url_for('dashboard', view='manage_account'))


@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    """Update a specific user's details."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        avatar_path = request.form.get('avatar_path', '')
        password = request.form['password']

        # Hash the password for security
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        query = "UPDATE users SET username = %s, role = %s, password = %s, avatar_path = %s WHERE id = %s"
        db_manager.execute_query(query, (username, role, hashed_password, avatar_path, user_id))
        db_manager.close_connection()

        return redirect(url_for('dashboard', view='view_list'))

    # Fetch user details for pre-filled form
    query = "SELECT username, role, avatar_path, password FROM users WHERE id = %s"
    user = db_manager.fetch_one(query, (user_id,))
    db_manager.close_connection()

    return render_template('update_user.html', user=user)


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    """Delete a specific user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db_manager = DatabaseManager()
    query = "DELETE FROM users WHERE id = %s"
    db_manager.execute_query(query, (user_id,))
    db_manager.close_connection()

    return redirect(url_for('dashboard', view='view_list'))


@app.route('/logout')
def logout():
    """Logout the current user and clear the session."""
    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
    
    
//dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard | Police Case Management System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <script src="{{ url_for('static', filename='js/dashboard.js') }}" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-left">
            <button id="toggle-sidebar-btn" class="header-btn">
                <i class="fa fa-bars"></i>
            </button>
            <span class="header-title">Police Case Management</span>
        </div>
        <div class="header-center" id="dropdown-container">
            <i class="fa fa-user"></i>
            <span id="logged-in-user">{{ username }}</span>
            <i id="dropdown-icon" class="fa fa-caret-down dropdown-icon"></i>
            <div class="dropdown-menu" id="dropdown-menu">
                <a href="{{ url_for('dashboard', view='manage_account') }}">Manage My Account</a>
                <a href="{{ url_for('login') }}">Logout</a>
            </div>
        </div>
    </header>

    <!-- Sidebar -->
    <aside id="sidebar" class="sidebar">
        <ul>
            <li><a href="{{ url_for('dashboard', view='cards') }}"><i class="nav-icon fas fa-tachometer-alt"></i> Dashboard</a></li>
            <li><a href="/create_case"><i class="fa fa-plus"></i> Add Case</a></li>
            <li><a href="/view_cases"><i class="nav-icon fas fa-scroll"></i> Case List</a></li>
            <li><a href="{{ url_for('dashboard', view='view_list') }}"><i class="fa fa-users"></i> User List</a></li>
            <li><a href="/reports"><i class="fa fa-chart-line"></i> Reports</a></li>
            <li><a href="{{ url_for('login') }}"><i class="fa fa-sign-out-alt"></i> Logout</a></li>
        </ul>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        {% if view == 'cards' %}
        <!-- Cards Section -->
        <section class="cards">
            <div class="card">
                <h3>Total Cases</h3>
                <p>{{ total_cases }}</p>
            </div>
            <div class="card">
                <h3>Pending Cases</h3>
                <p>{{ pending_cases }}</p>
            </div>
            <div class="card">
                <h3>Resolved Cases</h3>
                <p>{{ resolved_cases }}</p>
            </div>
            <div class="card">
                <h3>Cancelled Cases</h3>
                <p>{{ cancelled_cases }}</p>
            </div>
        </section>
        <!-- Decorative Image -->
        <section class="decorative-image">
            <img src="{{ url_for('static', filename='images/decorative.png') }}" alt="Decorative Image">
        </section>
        {% elif view == 'manage_account' %}
        <!-- Manage Account Section -->
        <section class="manage-account-section">
            <form method="POST" action="/manage_account" class="manage-account-form">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="{{ user.username }}" required>

                <label for="role">Role:</label>
                <input type="text" id="role" name="role" value="{{ user.role }}" required>

                <label for="password">Password:</label>
                <input type="password" id="password" name="password" placeholder="Enter new password" required>

                <button type="submit">Update</button>
            </form>
        </section>
        {% elif view == 'view_list' %}
        <!-- View Users Table -->
        <section class="view-users-section">
            <h2>User List</h2>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Role</th>
                        <th>Avatar Path</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.password }}</td>
                        <td>{{ user.role }}</td>
                        <td>{{ user.avatar_path }}</td>
                        <td>{{ user.created_at }}</td>
                        <td>
                            <a href="/update_user/{{ user.id }}"><i class="fa fa-edit"></i> Edit</a>
                            <a href="/delete_user/{{ user.id }}" onclick="return confirm('Are you sure you want to delete this user?')"><i class="fa fa-trash"></i> Delete</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% else %}
        <!-- Default Message -->
        <h2>Content Not Available</h2>
        {% endif %}
    </main>

    <!-- Footer -->
    <footer class="footer">
        Copyright &copy;&nbsp;&nbsp;<span id="current-year"></span>&nbsp;&nbsp;&nbsp; Police Case Management System
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <b>PCMS - Py (by: <a href="mailto=njebzncele@gmail.com/" target="blank">Son of all</a> )</b>&nbsp; v1.0
    </footer>
</body>
</html>

//login.py
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
    if request.method == 'POST':
        # Collect form data
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password using SHA256 for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Create a database connection
        db_manager = DatabaseManager()
        
        # Query the database for the user by username and hashed password
        query = "SELECT id, role FROM users WHERE username = %s AND password = %s"
        user = db_manager.fetch_one(query, (username, hashed_password))
        
        db_manager.close_connection()
        
        if user:
            # Store the user's information in the session
            session['user_id'] = user['id']
            session['username'] = username
            session['role'] = user['role']

            # Redirect to the dashboard if successful
            return redirect(url_for('dashboard'))
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
    
    # Pass the username from the session to the template
    return render_template('dashboard.html', username=session.get('username'))

if __name__ == "__main__":
    app.run(debug=True)

//login.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Police Case Management System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}"> <!-- Relative path to static file -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

    <style>
        html, body{
          height:calc(100%) !important;
          width:calc(100%) !important;
        }
        body{
          background-image: url("{{ url_for('static', filename='images/decorative.png') }}");
          background-size:cover;
          background-repeat:no-repeat;
        }
        .login-title{
          text-shadow: 2px 2px black
        }
        #login{
          flex-direction:column !important
        }
        #logo-img{
            height:150px;
            width:150px;
            object-fit:scale-down;
            object-position:center center;
            border-radius:100%;
        }
        #login .col-7,#login .col-5{
          width: 100% !important;
          max-width:unset !important
        }
      </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        {% if error %}
        <p style="color: red;">{{ error }}</p>
        {% endif %}
        <form id="login-form" method="POST" action="/login">
            <label for="username">Username<span class="fas fa-user"></span></label>
            <input type="text" id="username" name="username" required>

            <label for="password">Password <span class="fas fa-lock"></span></label>
            <input type="password" id="password" name="password" required>

            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>

//base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Base | Police Case Management System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}"> <!-- Link to shared CSS -->
    <script src="{{ url_for('static', filename='js/sidebar.js') }}" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        html, body{
          height:calc(100%) !important;
          width:calc(100%) !important;
        }
        body{
          background-image: url("{{ url_for('static', filename='images/decorative.png') }}");
          background-size:cover;
          background-repeat:no-repeat;
        }
        .login-title{
          text-shadow: 2px 2px black
        }
        #login{
          flex-direction:column !important
        }
        #logo-img{
            height:150px;
            width:150px;
            object-fit:scale-down;
            object-position:center center;
            border-radius:100%;
        }
        #login .col-7,#login .col-5{
          width: 100% !important;
          max-width:unset !important
        }
      </style>
</head>
<body>
    <div class="base-container">
        <div class="col-7 h-100 d-flex align-items-center justify-content-center">
            <div class="w-100">
              <center><img src="{{ url_for('static', filename='images/logo.png') }}" alt="logo" id="logo-img"></center>
              <h1 class="text-center py-5 login-title"><b></b></h1>
            </div>
          </div>
        <p><b><i>Police Case Management System</b></i></p>
        <div class="buttons">
            <button onclick="window.location.href='/login'">Login</button>
            <button onclick="window.close()">Exit</button>
        </div>
        <p>
            &copy;&nbsp;&nbsp;<span id="current-year"></span>&nbsp;&nbsp;&nbsp; Police Case Management System
        </p>
    </div>
</body>
</html>

//view_list.py
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

//manage_account.py
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
	
//manage_account.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage My Account</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <header class="header">
        <div class="header-left">
            <span class="header-title">Manage My Account</span>
        </div>
    </header>

    <main class="main-content">
        <form method="POST" action="/manage_account" class="manage-account-form">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" value="{{ user.username }}" required>

            <label for="role">Role:</label>
            <input type="text" id="role" name="role" value="{{ user.role }}" required>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" value="{{ user.password }}" required>

            <button type="submit">Update</button>
        </form>
    </main>
</body>
</html>


//update_user.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update User</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <form method="POST" action="/update_user/{{ user.id }}" class="update-user-form">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" value="{{ user.username }}" required>

        <label for="role">Role:</label>
        <input type="text" id="role" name="role" value="{{ user.role }}" required>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" placeholder="Enter new password" required>

        <label for="avatar_path">Avatar Path:</label>
        <input type="text" id="avatar_path" name="avatar_path" value="{{ user.avatar_path }}" required>

        <button type="submit">Save Changes</button>
    </form>
</body>
</html>

//create_account.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account | Police Case Management System</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}"> <!-- Link to your stylesheet -->

    <style>
        html, body{
          height:calc(100%) !important;
          width:calc(100%) !important;
        }
        body{
          background-image: url("{{ url_for('static', filename='images/decorative.png') }}");
          background-size:cover;
          background-repeat:no-repeat;
        }
        .login-title{
          text-shadow: 2px 2px black
        }
        #login{
          flex-direction:column !important
        }
        #logo-img{
            height:150px;
            width:150px;
            object-fit:scale-down;
            object-position:center center;
            border-radius:100%;
        }
        #login .col-7,#login .col-5{
          width: 100% !important;
          max-width:unset !important
        }
      </style>
</head>
<body>
    <div class="login-container">
    <div class="create-account-container">
        <h2>Create Account</h2>
        {% if error %}
        <p style="color: red;">{{ error }}</p>
        {% endif %}
        {% if success %}
        <p style="color: green;">{{ success }}</p>
        {% endif %}
        <form id="create-account-form" method="POST" action="/create_account">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            
            <label for="role">Role:</label>
            <select id="role" name="role" required>
                <option value="Admin">Admin</option>
                <option value="Officer">Officer</option>
                <option value="Clerk">Clerk</option>
            </select>
            
            <label for="avatar_path">Avatar Path:</label>
            <input type="text" id="avatar_path" name="avatar_path" placeholder="/path/to/avatar.jpg" required>
            
            <button type="submit">Create Account</button>
        </form>
    </div>
</div>
</body>
</html>


//create_account.py
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
	
	
//		    
