from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import pyotp
import json
import os
from io import BytesIO
import qrcode
import cv2
import face_recognition
import numpy as np

# Flask App Initialization
app = Flask(__name__)
app.secret_key = "nova4i2"  # Change to a strong random key

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "nova47449@gmail.com"  # Replace with your email
app.config['MAIL_PASSWORD'] = "ssae bxmf canz tibq"  # Replace with your app password
mail = Mail(app)

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Serializer for Password Reset
serializer = URLSafeTimedSerializer(app.secret_key)

# Users File
USERS_FILE = 'users.json'

# Ensure Users File Exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)

# Helper Functions
def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def capture_face_encoding():
    """Captures and returns the user's face encoding from the webcam."""
    video_capture = cv2.VideoCapture(0)
    print("Please look at the camera...")

    face_encoding = None
    for i in range(50):  # Try for 50 frames
        ret, frame = video_capture.read()
        if not ret:
            continue

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        if face_encodings:
            face_encoding = face_encodings[0]
            break

    video_capture.release()
    cv2.destroyAllWindows()
    return face_encoding

# Routes
@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users:
            flash("User already exists.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        totp_secret = pyotp.random_base32()

        # Capture face encoding
        face_encoding = capture_face_encoding()
        if face_encoding is None:
            flash("Face not detected. Please try again.")
            return redirect(url_for('register'))

        # Initialize User Data
        users[username] = {
            'password': hashed_password,
            'totp_secret': totp_secret,
            'portfolio': "<h1>Welcome to Your Portfolio!</h1><p>Start editing here...</p>",
            'face_encoding': face_encoding.tolist()  # Convert numpy array to list for JSON
        }
        save_users(users)

        flash("Registration successful! Please scan the QR code for MFA.")
        return render_template('totp_qr.html', username=username)
    return render_template('register.html')

@app.route('/totp_qr/<username>')
def totp_qr(username):
    users = load_users()
    user = users.get(username)
    if not user:
        flash("User not found.")
        return redirect(url_for('register'))

    totp = pyotp.TOTP(user['totp_secret'])
    provisioning_uri = totp.provisioning_uri(username, issuer_name="SecureMFA")

    buffer = BytesIO()
    qr_code = qrcode.make(provisioning_uri)
    qr_code.save(buffer)
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            flash("Login successful! Enter your TOTP.")
            return redirect(url_for('verify_otp'))

        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        username = session.get('username')
        if not username:
            flash("Session expired. Please log in again.")
            return redirect(url_for('login'))

        users = load_users()
        totp = pyotp.TOTP(users[username]['totp_secret'])
        if totp.verify(otp):
            flash("OTP verified! Welcome to your portfolio.")
            return redirect(url_for('portfolio'))
        else:
            flash("Invalid OTP. Please try again.")
    return render_template('verify_otp.html')

@app.route('/face_login', methods=['POST'])
def face_login():
    face_encoding = capture_face_encoding()
    if face_encoding is None:
        flash("No face detected. Please try again.")
        return redirect(url_for('login'))

    users = load_users()
    for username, user_data in users.items():
        stored_face_encoding = np.array(user_data.get('face_encoding'))
        matches = face_recognition.compare_faces([stored_face_encoding], face_encoding)
        if matches[0]:  # If match is found
            session['username'] = username
            flash("Face recognized! Welcome back.")
            return redirect(url_for('portfolio'))

    flash("Face not recognized. Please try again or log in manually.")
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        users = load_users()

        if email not in users:
            flash("Email not found.")
            return redirect(url_for('forgot_password'))

        token = serializer.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)

        msg = Message(
            subject="Password Reset Request",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Click the link to reset your password: {reset_url}"
        mail.send(msg)

        flash("Password reset link sent to your email.")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("The password reset link is invalid or has expired.")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('reset_password', token=token))

        users = load_users()
        users[email]['password'] = generate_password_hash(password)
        save_users(users)

        flash("Password reset successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/portfolio', methods=['GET', 'POST'])
def portfolio():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    users = load_users()
    user_data = users.get(username)

    if request.method == 'POST':
        # Save portfolio content
        content = request.form.get('content')

        # Handle image upload
        if 'image' in request.files:
            image = request.files['image']
            if image.filename != '':
                # Save the uploaded image to the static/uploads directory
                image_path = os.path.join('static/uploads', f"{username}_{image.filename}")
                image.save(image_path)

                # Add the image URL to the portfolio content
                image_url = f"/static/uploads/{username}_{image.filename}"
                content += f'<img src="{image_url}" alt="Uploaded Image" style="max-width: 100%; height: auto;">'

        # Update the user's portfolio content
        users[username]['portfolio'] = content
        save_users(users)
        flash("Portfolio updated successfully!")

    return render_template('portfolio.html', content=user_data.get('portfolio', ''))



@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)