from flask import Flask, request, jsonify, render_template, redirect, url_for
import cv2
import numpy as np
import mediapipe as mp
import mysql.connector
import json
from sklearn.neighbors import KNeighborsClassifier

app = Flask(__name__, template_folder="templates")

# Initialize Mediapipe Face Detection
mp_face_detection = mp.solutions.face_detection
face_detector = mp_face_detection.FaceDetection(model_selection=1, min_detection_confidence=0.5)

# Database Configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "police_case_management"
}


def connect_db():
    """Ensures database connection is valid."""
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return None


@app.route('/')
def base():
    """Serve the face login page."""
    return render_template('login_face.html')


@app.route('/register_user', methods=['POST'])
def register_user():
    """Stores user details in the database BEFORE capturing face."""

    username = request.form['username'].strip()
    role = request.form['role'].strip()
    email = request.form['email'].strip()
    password = request.form['password'].strip()
    avatar_path = request.form['avatar_path'].strip()

    if not username or not role or not email or not password:
        return jsonify({"error": "All fields are required!"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = conn.cursor()
    try:
        query = "INSERT INTO users (username, role, email, password, avatar_path) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (username, role, email, password, avatar_path))
        conn.commit()
    except mysql.connector.IntegrityError:
        return jsonify({"error": "Username already exists. Choose a different one!"}), 400
    finally:
        conn.close()

    return jsonify({"success": True})


@app.route('/register_face', methods=['POST'])
def register_face():
    """Captures face encoding and updates the user record."""

    username = request.form['username'].strip()
    frame, face_encoding = capture_face()

    if face_encoding is None:
        return jsonify({"error": "Face not detected. Try again!"}), 400

    conn = connect_db()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = conn.cursor()
    query = "UPDATE users SET face_encoding = %s WHERE username = %s"
    cursor.execute(query, (face_encoding, username))
    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route('/login_face', methods=['POST'])
def login_face():
    """Validates user face using trained KNN model."""

    frame, face_encoding = capture_face()
    if face_encoding is None:
        return jsonify({"error": "Face not detected. Try again!"}), 400

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, email, avatar_path, face_encoding FROM users")
    users = cursor.fetchall()
    conn.close()

    X_train = []
    y_train = []

    for user in users:
        try:
            if user[4]:  # ✅ Ensure the encoding is not empty or NULL
                X_train.append(json.loads(user[4]))
                y_train.append(user[0])
        except json.decoder.JSONDecodeError:
            print(f"Error: Skipping invalid encoding for user {user[0]}")  # ✅ Debugging

    if not X_train:
        return jsonify({"error": "No valid face encodings found. Please re-register your face!"}), 400

    knn = KNeighborsClassifier(n_neighbors=3)
    knn.fit(X_train, y_train)

    prediction = knn.predict([json.loads(face_encoding)])

    for user in users:
        if user[0] == prediction[0]:
            return jsonify({"success": True, "username": user[0], "redirect": "/dashboard"}), 200

    return jsonify({"error": "Face not recognized."}), 403


def capture_face():
    """Captures a face using the laptop webcam and ensures proper format for processing."""

    video_capture = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    if not video_capture.isOpened():
        print("Error: Laptop camera not accessible.")
        return None, None

    ret, frame = video_capture.read()

    if not ret or frame is None:
        print("Error: Failed to read frame—image is empty!")
        video_capture.release()
        return None, None

    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    face_results = face_detector.process(frame_rgb)

    if face_results.detections:
        keypoints = [[kp.x, kp.y] for kp in
                     face_results.detections[0].location_data.relative_keypoints]  # ✅ Store `x, y` keypoints
        video_capture.release()
        return frame, json.dumps(keypoints)

    video_capture.release()
    return None, None


def train_encodings(username):
    """Collects multiple face images to train and store encodings."""

    video_capture = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    if not video_capture.isOpened():
        print("Error: Laptop camera not accessible.")
        return []

    encodings = []
    count = 0

    while count < 10:  # ✅ Collect 10 training images
        ret, frame = video_capture.read()

        if not ret or frame is None:
            print("Error: Failed to read frame—image is empty!")
            continue

        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_results = face_detector.process(frame_rgb)

        if face_results.detections:
            for detection in face_results.detections:
                keypoints = [[kp.x, kp.y] for kp in detection.location_data.relative_keypoints]  # ✅ Store only `x, y`
                encodings.append(json.dumps(keypoints))
                count += 1

        cv2.imshow("Training Face Data", frame)
        cv2.waitKey(100)

    video_capture.release()
    cv2.destroyAllWindows()
    print("✅ Training data collection complete!")
    return encodings


@app.route('/dashboard')
def dashboard():
    """Displays user details on dashboard."""
    username = request.args.get('username')
    role = request.args.get('role')

    return render_template("dashboard.html", username=username, role=role)

if __name__ == '__main__':
    app.run(debug=True)
