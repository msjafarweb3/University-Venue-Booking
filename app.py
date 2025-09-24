# app.py

import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, Response
from firebase_admin import credentials, initia3lize_app, auth, firestore
import datetime # Keep datetime for type checking
# Removed explicit Timestamp import from google.cloud.firestore or google.cloud.firestore_v1.types
import uuid # For generating unique IDs for bookings and users if not using Firebase Auth UIDs directly
import re # For email validation
import io # For in-memory file operations for CSV export
import csv # For CSV writing
import requests # Added for making HTTP requests to Firebase REST API

# Import ReportLab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

# For timezone awareness in datetime objects
import pytz # Import pytz

# For sending emails
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
# IMPORTANT: Replace with a strong, random secret key in production!
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# --- Firebase Admin SDK Initialization ---
# Ensure your serviceAccountKey.json is in the same directory as app.py
try:
    cred = credentials.Certificate("serviceAccountKey.json")
    initialize_app(cred)
    db = firestore.client()
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")
    print("Please ensure 'serviceAccountKey.json' is correctly placed and valid.")
    exit(1) # Exit if Firebase cannot be initialized

# Define a default app_id for local development.
# In a Canvas environment, __app_id would be provided.
APP_ID = os.environ.get('CANVAS_APP_ID', 'default-venue-booking-app')

# --- Firebase Web API Key for client-side and direct API calls ---
# This is crucial for signInWithPassword REST API call
# Get this from your Firebase Project settings -> Project settings -> General -> Your apps -> Web app -> Firebase SDK snippet -> Config
FIREBASE_WEB_API_KEY = os.environ.get('FIREBASE_WEB_API_KEY', '') # REPLACE WITH YOUR ACTUAL WEB API KEY!

# --- Email Configuration (Replace with your actual details) ---
# For a real application, use environment variables for these
EMAIL_ADDRESS = os.environ.get('EMAIL_USER', '') # e.g., "your_email@gmail.com"
EMAIL_PASSWORD = os.environ.get('EMAIL_PASS', '') # Your app password or actual password
SMTP_SERVER = os.environ.get('SMTP_HOST', 'smtp.gmail.com') # e.g., 'smtp.gmail.com' for Gmail
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587)) # 587 for TLS, 465 for SSL

def send_email_notification(recipient_email, subject, body_plain, body_html=None):
    """Sends a general email notification."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("Email credentials not set. Skipping email sending.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient_email

        part1 = MIMEText(body_plain, "plain")
        msg.attach(part1)

        if body_html:
            part2 = MIMEText(body_html, "html")
            msg.attach(part2)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, recipient_email, msg.as_string())
        print(f"Email sent to {recipient_email} for subject: {subject}")
        return True
    except Exception as e:
        print(f"Failed to send email to {recipient_email}: {e}")
        return False

def send_booking_notification_email(recipient_email, recipient_name, booking_details, status):
    """Sends an email notification for booking status."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("Email credentials not set. Skipping email sending.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg['Subject'] = f"Venue Booking Request {status.title()}"
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient_email

        # Create the plain-text and HTML versions of your message
        text = f"""
        Dear {recipient_name},

        Your booking for {booking_details['venue_name']} on {booking_details['date']} from {booking_details['start_time']} to {booking_details['end_time']}
        for the purpose of {booking_details['purpose']} has been {status}.
        Course: {booking_details.get('course', 'N/A')}

        Booking Details:
        Venue: {booking_details['venue_name']}
        Date: {booking_details['date']}
        Time: {booking_details['start_time']} - {booking_details['end_time']}
        Purpose: {booking_details['purpose']}
        Course: {booking_details.get('course', 'N/A')}
        Attendees: {booking_details['attendees']}
        Status: {status.title()}

        Thank you,
        Nasarawa State University, Keffi Venue Booking System
        """
        html = f"""
        <html>
            <body>
                <p>Dear {recipient_name},</p>
                <p>Your booking for <strong>{booking_details['venue_name']}</strong> on <strong>{booking_details['date']}</strong> from <strong>{booking_details['start_time']}</strong> to <strong>{booking_details['end_time']}</strong>
                for the purpose of <strong>{booking_details['purpose']}</strong> has been <strong style="color: {'green' if status == 'approved' else 'red'};">{status.title()}</strong>.</p>
                <p><strong>Course:</strong> {booking_details.get('course', 'N/A')}</p>
                <p><strong>Booking Details:</strong></p>
                <ul>
                    <li><strong>Venue:</strong> {booking_details['venue_name']}</li>
                    <li><strong>Date:</strong> {booking_details['date']}</li>
                    <li><strong>Time:</strong> {booking_details['start_time']} - {booking_details['end_time']}</li>
                    <li><strong>Purpose:</strong> {booking_details['purpose']}</li>
                    <li><strong>Course:</strong> {booking_details.get('course', 'N/A')}</li>
                    <li><strong>Attendees:</strong> {booking_details['attendees']}</li>
                    <li><strong>Status:</strong> <span style="color: {'green' if status == 'approved' else 'red'};">{status.title()}</span></li>
                </ul>
                <p>Thank you,</p>
                <p>Nasarawa State University, Keffi Venue Booking System</p>
            </body>
        </html>
        """

        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")

        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, recipient_email, msg.as_string())
        print(f"Email sent to {recipient_email} for booking {booking_details.get('id', 'N/A')} status: {status}")
        return True
    except Exception as e:
        print(f"Failed to send email to {recipient_email}: {e}")
        return False

# --- Helper to validate if a string is an email ---
def is_email(text):
    # Basic regex for email validation
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", text)

# --- Authentication Routes ---

@app.route('/')
def index():
    """Redirects to the login page."""
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    """Renders the login HTML page."""
    return render_template('login.html')

@app.route('/register')
def register_page():
    """Renders the registration HTML page."""
    return render_template('Register.html')

@app.route('/register', methods=['POST'])
def register():
    """Handles new user registration."""
    data = request.get_json()
    role = data.get('role')
    fullname = data.get('fullname')
    email = data.get('email')
    password = data.get('password')
    matric_no = data.get('matric_no') # Retrieve matric_no

    if not all([role, fullname, email, password]):
        return jsonify({"error": "All fields are required."}), 400

    # Validate matric_no presence for student role only (staff role removed)
    if role == 'student' and not matric_no:
        return jsonify({"error": "Matriculation Number is required for student registration."}), 400

    # Admins do not require a matric_no, ensure it's not present if submitted for admin
    if role == 'admin' and matric_no:
        matric_no = None

    try:
        # Check if email already exists in Firebase Auth
        try:
            auth.get_user_by_email(email)
            return jsonify({"error": "Email already registered."}), 409
        except auth.UserNotFoundError:
            pass # Email does not exist, proceed with creation

        # Check if matric_no already exists in Firestore for student
        if role == 'student':
            existing_user_by_matric = db.collection('artifacts').document(APP_ID).collection('users').where('matric_no', '==', matric_no).limit(1).get()
            if existing_user_by_matric:
                return jsonify({"error": "Matriculation Number already registered."}), 409

        # Create user in Firebase Authentication
        user = auth.create_user(email=email, password=password)

        # Store additional user details (role, fullname, matric_no) in Firestore
        user_doc_ref = db.collection('artifacts').document(APP_ID).collection('users').document(user.uid)
        user_doc_ref.set({
            'fullname': fullname,
            'email': email,
            'role': role,
            'matric_no': matric_no if role == 'student' else None, # Store matric_no only for student
            'is_approved': False, # New users need admin approval
            'profile_picture_url': '', # New field for profile picture
            'created_at': firestore.SERVER_TIMESTAMP
        })

        # Send approval email to admin
        admin_email = os.environ.get('ADMIN_EMAIL')
        if admin_email:
            subject = "New User Registration Awaiting Approval"
            body_plain = f"A new user, {fullname} ({email}, Matric No: {matric_no if matric_no else 'N/A'}), has registered as a {role} and is awaiting your approval."
            body_html = f"""
                <html>
                    <body>
                        <p>A new user, <strong>{fullname}</strong> (<strong>{email}</strong>, Matric No: {matric_no if matric_no else 'N/A'}), has registered as a <strong>{role}</strong> and is awaiting your approval.</p>
                        <p>Please log into the admin dashboard to review and approve the registration.</p>
                    </body>
                </html>
            """
            send_email_notification(admin_email, subject, body_plain, body_html)
            print(f"Approval email sent to admin: {admin_email}")
        else:
            print("ADMIN_EMAIL environment variable not set. Skipping approval email.")

        return jsonify({"message": "Registration successful! Awaiting admin approval."}), 201
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
def login():
    """Handles user login by verifying Firebase credentials (email/password) or matric_no/password."""
    data = request.get_json()
    identifier = data.get('identifier') # This can be email or matric_no
    password = data.get('password')
    requested_role = data.get('role')

    if not identifier or not password or not requested_role:
        return jsonify({"error": "Missing required login information."}), 400

    user_email_to_auth = None
    user_uid_from_auth = None

    try:
        if is_email(identifier):
            user_email_to_auth = identifier
        else:
            # If identifier is not an email, assume it's a matric_no
            users_ref = db.collection('artifacts').document(APP_ID).collection('users')
            users_by_matric = users_ref.where('matric_no', '==', identifier).limit(1).get()

            if not users_by_matric:
                return jsonify({"error": "User with this Matriculation Number not found."}), 404

            user_doc = users_by_matric[0]
            user_data_from_firestore = user_doc.to_dict()
            user_email_to_auth = user_data_from_firestore.get('email')
            user_uid_from_auth = user_doc.id # Get UID from Firestore doc ID

            if not user_email_to_auth:
                return jsonify({"error": "User data inconsistent. Email not found for this ID."}), 500

        # --- Perform password authentication against Firebase Identity Platform REST API ---
        # This is the crucial step that was missing for proper password verification.
        # It sends a request to Firebase's authentication endpoint.
        rest_api_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
        payload = {
            "email": user_email_to_auth,
            "password": password,
            "returnSecureToken": True # Request a secure token upon successful authentication
        }
        rest_response = requests.post(rest_api_url, json=payload)
        auth_data = rest_response.json()

        if not rest_response.ok:
            # Handle various authentication errors returned by Firebase
            error_code = auth_data.get('error', {}).get('message', 'UNKNOWN_ERROR')
            print(f"Firebase REST API authentication error: {error_code}")

            if error_code == "EMAIL_NOT_FOUND" or error_code == "INVALID_PASSWORD":
                return jsonify({"error": "Invalid email/ID or password."}), 401
            elif error_code == "USER_DISABLED":
                return jsonify({"error": "Your account is disabled. Please contact support."}), 403
            else:
                return jsonify({"error": f"Authentication failed: {error_code}"}), 401

        # If REST API authentication is successful, get the user's UID
        user_uid_from_auth = auth_data.get('localId')

        # Fetch user details from Firestore to get role and approval status
        user_doc_from_firestore = db.collection('artifacts').document(APP_ID).collection('users').document(user_uid_from_auth).get()
        if not user_doc_from_firestore.exists:
            return jsonify({"error": "User data not found in database after successful authentication."}), 404

        user_data = user_doc_from_firestore.to_dict()
        stored_role = user_data.get('role')
        is_approved = user_data.get('is_approved', False)
        stored_matric_no_from_db = user_data.get('matric_no')
        profile_picture_url = user_data.get('profile_picture_url', '')


        # Role verification: Ensure the user's stored role matches the requested role
        if stored_role != requested_role:
            return jsonify({"error": f"Access denied. You are registered as a {stored_role}, not {requested_role}."}), 403

        # Approval status verification: User must be approved by an admin
        if not is_approved:
            return jsonify({"error": "Your account is pending admin approval. Please wait."}), 403

        # If identifier was a matric number, ensure it matches the stored one (only for student role)
        if requested_role == 'student' and not is_email(identifier) and stored_matric_no_from_db and identifier != stored_matric_no_from_db:
            return jsonify({"error": "Matriculation Number mismatch."}), 403

        # Set Flask session variables upon successful and verified login
        session['user_id'] = user_uid_from_auth
        session['user_email'] = user_email_to_auth
        session['user_role'] = stored_role
        session['fullname'] = user_data.get('fullname')
        session['matric_no'] = stored_matric_no_from_db
        session['profile_picture_url'] = profile_picture_url # Store profile picture URL in session

        return jsonify({"message": "Login successful!", "role": stored_role}), 200

    except Exception as e:
        print(f"Login backend error: {e}")
        return jsonify({"error": "An internal error occurred during login."}), 500

@app.route('/forgot_password_page')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required."}), 400

    try:
        # Generate the password reset link using Firebase Admin SDK.
        auth.generate_password_reset_link(email)
        return jsonify({"message": "Password reset link sent to your email."}), 200
    except auth.UserNotFoundError:
        # For security, don't reveal if the email exists or not
        return jsonify({"message": "If your email is registered, a password reset link has been sent."}), 200
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return jsonify({"error": f"Failed to send password reset email: {str(e)}"}), 500


@app.route('/logout')
def logout():
    """Handles user logout."""
    session.clear()
    return redirect(url_for('login_page'))

# --- Dashboard Routes ---

@app.route('/student/dashboard')
def student_dashboard():
    """Renders the student dashboard."""
    if 'user_id' not in session or session.get('user_role') != 'student': # Only allow student
        return redirect(url_for('login_page'))
    user_data = {
        'fullname': session.get('fullname'),
        'email': session.get('user_email'),
        'matric_no': session.get('matric_no'), # Pass matric_no
        'profile_picture_url': session.get('profile_picture_url', '') # Pass profile picture URL
    }
    initial_auth_token = None
    try:
        # Generate a custom Firebase ID token for the client-side
        # This token is valid for 1 hour by default
        custom_token_bytes = auth.create_custom_token(session['user_id'])
        # Decode to string as it's bytes
        initial_auth_token = custom_token_bytes.decode('utf-8')
        print(f"Generated custom token for {session['user_id']}: {initial_auth_token[:20]}...") # Log for debugging
    except Exception as e:
        print(f"Error generating custom token for student dashboard: {e}")
        # Optionally, clear session and redirect to login if token generation fails
        session.clear()
        return redirect(url_for('login_page', error="Failed to authenticate dashboard session."))

    return render_template('dashboard.html', user=user_data, __initial_auth_token=initial_auth_token)

# Removed @app.route('/staff/dashboard') and staff_dashboard()

@app.route('/admin/dashboard')
def admin_dashboard():
    """Renders the admin dashboard."""
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login_page'))
    user_data = {
        'fullname': session.get('fullname'),
        'email': session.get('user_email'),
        'matric_no': session.get('matric_no'), # Admin might not have one, but for consistency
        'profile_picture_url': session.get('profile_picture_url', '') # Pass profile picture URL
    }
    initial_auth_token = None
    try:
        custom_token_bytes = auth.create_custom_token(session['user_id'])
        initial_auth_token = custom_token_bytes.decode('utf-8')
        print(f"Generated custom token for admin dashboard: {initial_auth_token[:20]}...")
    except Exception as e:
        print(f"Error generating custom token for admin dashboard: {e}")
        session.clear()
        return redirect(url_for('login_page', error="Failed to authenticate dashboard session."))

    return render_template('admin_dashboard.html', user=user_data, __initial_auth_token=initial_auth_token)

# --- API Endpoints for User Profile (Shared for Student/Admin) ---
@app.route('/api/user_profile', methods=['GET'])
def get_user_profile():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401
    try:
        user_doc = db.collection('artifacts').document(APP_ID).collection('users').document(session['user_id']).get()
        if not user_doc.exists:
            return jsonify({"error": "User profile not found."}), 404
        user_data = user_doc.to_dict()
        # Only return necessary fields for the profile page
        return jsonify({
            "user": {
                "fullname": user_data.get('fullname'),
                "email": user_data.get('email'),
                "matric_no": user_data.get('matric_no'),
                "role": user_data.get('role'),
                "profile_picture_url": user_data.get('profile_picture_url', '') # Include profile picture URL
            }
        }), 200
    except Exception as e:
        print(f"Error fetching user profile: {e}")
        return jsonify({"error": f"Failed to fetch user profile: {str(e)}"}), 500

@app.route('/api/user_profile', methods=['PUT'])
def update_user_profile():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401
    data = request.get_json()
    fullname = data.get('fullname')
    matric_no = data.get('matric_no') # Can be matric_no
    profile_picture_url = data.get('profile_picture_url') # New field for profile picture URL

    if not fullname:
        return jsonify({"error": "Full name is required."}), 400

    user_ref = db.collection('artifacts').document(APP_ID).collection('users').document(session['user_id'])
    try:
        update_data = {'fullname': fullname}
        # Only update matric_no if the user's role is student
        if session.get('user_role') == 'student':
            if matric_no is not None: # Allow updating or clearing matric_no
                update_data['matric_no'] = matric_no
            else: # If matric_no is required for their role but not provided, return error
                return jsonify({"error": "Matriculation Number is required for your role."}), 400
        elif session.get('user_role') == 'admin':
            # Admins might not have a matric_no, so we can allow it to be optional or not updated
            if matric_no is not None: # Admin can update their matric_no if they have one
                update_data['matric_no'] = matric_no
            elif 'matric_no' in user_ref.get().to_dict() and matric_no is None: # Allow admin to clear matric_no
                update_data['matric_no'] = firestore.DELETE_FIELD

        if profile_picture_url is not None: # Update profile picture URL if provided
            update_data['profile_picture_url'] = profile_picture_url

        user_ref.update(update_data)
        session['fullname'] = fullname # Update session
        session['matric_no'] = matric_no # Update session
        session['profile_picture_url'] = profile_picture_url # Update session for profile picture
        return jsonify({"message": "Profile updated successfully!"}), 200
    except Exception as e:
        print(f"Error updating user profile: {e}")
        return jsonify({"error": f"Failed to update profile: {str(e)}"}), 500

@app.route('/api/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({"error": "Current password and new password are required."}), 400

    try:
        user = auth.get_user(session['user_id'])
        # Firebase Admin SDK doesn't directly verify current password.
        # This is typically handled client-side by re-authenticating the user.
        # If this is to be server-side, you'd need to use a custom token exchange
        # or have the client send a fresh ID token after re-auth.
        # For this example, we'll assume the client-side Firebase SDK has already
        # handled re-authentication and validated the current password before sending
        # the request to this endpoint. This endpoint will just set the new password.
        auth.update_user(user.uid, password=new_password)
        return jsonify({"message": "Password changed successfully!"}), 200
    except auth.UserNotFoundError:
        return jsonify({"error": "User not found."}), 404
    except Exception as e:
        print(f"Error changing password: {e}")
        return jsonify({"error": f"Failed to change password: {str(e)}"}), 500


# --- API Endpoints for Bookings (Shared) ---
@app.route('/api/bookings', methods=['POST'])
def create_booking():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401

    data = request.get_json()
    venue_id = data.get('venue_id')
    date_str = data.get('date') # Date as string (YYYY-MM-DD)
    start_time_str = data.get('start_time')
    end_time_str = data.get('end_time')
    purpose = data.get('purpose')
    attendees = data.get('attendees')
    course = data.get('course', '') # New field: course, default to empty string


    if not all([venue_id, date_str, start_time_str, end_time_str, purpose, attendees]):
        return jsonify({"error": "Missing required booking fields."}), 400

    try:
        # Get UTC timezone object
        utc_timezone = pytz.utc

        # Combine date and time strings for datetime objects, then localize to UTC
        start_datetime_naive = datetime.datetime.strptime(f"{date_str} {start_time_str}", "%Y-%m-%d %H:%M")
        end_datetime_naive = datetime.datetime.strptime(f"{date_str} {end_time_str}", "%Y-%m-%d %H:%M")

        # Make datetimes timezone-aware (UTC) for consistent comparison with Firestore Timestamps
        start_datetime = utc_timezone.localize(start_datetime_naive)
        end_datetime = utc_timezone.localize(end_datetime_naive)

        if start_datetime >= end_datetime:
            return jsonify({"error": "End time must be after start time."}), 400

        # Fetch venue details to get its name
        venue_doc = db.collection('artifacts').document(APP_ID).collection('venues').document(venue_id).get()
        if not venue_doc.exists:
            return jsonify({"error": "Selected venue not found."}), 404
        venue_data = venue_doc.to_dict()
        venue_name = venue_data.get('name')

        # Check for Auditorium maintenance (Friday 2PM-6PM)
        if venue_name.upper() == 'AUDITORIUM' and start_datetime.weekday() == 4: # Friday is 4 (0=Monday, 6=Sunday)
            maintenance_start_time = datetime.time(14, 0) # 2 PM
            maintenance_end_time = datetime.time(18, 0)   # 6 PM

            # Ensure booking start/end times are also converted to timezone-aware for comparison
            # Or convert maintenance times to timezone-aware too if comparing time objects
            # For simplicity, comparing just time components (which are naive) is okay here.
            if (start_datetime.time() < maintenance_end_time and end_datetime.time() > maintenance_start_time):
                return jsonify({"error": "Auditorium is unavailable for maintenance on Fridays from 2PM-6PM."}), 400


        # Check for overlapping bookings for the same venue
        bookings_ref = db.collection('artifacts').document(APP_ID).collection('bookings')
        # Query for bookings on the same date for the specific venue
        overlapping_bookings_query = bookings_ref.where('venue_id', '==', venue_id).where('date', '==', date_str).get()

        for booking_doc in overlapping_bookings_query:
            existing_booking = booking_doc.to_dict()
            # Convert Firestore Timestamp to datetime objects for comparison, ensuring UTC awareness
            # Firestore Timestamp objects when retrieved using .to_dict() often return timezone-aware datetimes
            # If they are naive, this conversion makes them UTC-aware for consistency.
            existing_start_dt = existing_booking['start_datetime']
            existing_end_dt = existing_booking['end_datetime']
            
            # Ensure both existing and new datetimes are UTC-aware for comparison
            if existing_start_dt.tzinfo is None:
                existing_start_dt = utc_timezone.localize(existing_start_dt)
            else:
                existing_start_dt = existing_start_dt.astimezone(utc_timezone)

            if existing_end_dt.tzinfo is None:
                existing_end_dt = utc_timezone.localize(existing_end_dt)
            else:
                existing_end_dt = existing_end_dt.astimezone(utc_timezone)


            # Check for overlap: (start1 < end2) and (end1 > start2)
            if (start_datetime < existing_end_dt and end_datetime > existing_start_dt and
                existing_booking['status'] in ['pending', 'approved']):
                return jsonify({"error": "Venue is already booked for this time slot. Please choose another time."}), 409

        # Generate a unique booking ID
        booking_id = str(uuid.uuid4())

        booking_data = {
            'booking_id': booking_id,
            'venue_id': venue_id,
            'venue_name': venue_name, # Store venue name for easier display
            'date': date_str,
            'start_time': start_time_str,
            'end_time': end_time_str,
            'start_datetime': start_datetime, # Store as datetime object for easier comparison
            'end_datetime': end_datetime,     # Store as datetime object for easier comparison
            'purpose': purpose,
            'course': course, # Store the course
            'attendees': attendees,
            'booked_by_uid': session['user_id'],
            'booked_by_email': session['user_email'],
            'booked_by_fullname': session.get('fullname', 'N/A'),
            'booked_by_matric_no': session.get('matric_no', 'N/A'), # Store matric_no
            'status': 'pending', # All new bookings require admin approval
            'email_sent': False, # Flag to track if email was sent
            'requested_on': firestore.SERVER_TIMESTAMP
        }

        db.collection('artifacts').document(APP_ID).collection('bookings').document(booking_id).set(booking_data)

        # Notify admin about new booking
        admin_email = os.environ.get('ADMIN_EMAIL')
        if admin_email:
            subject = "New Venue Booking Awaiting Approval"
            body_plain = f"A new booking for venue '{venue_name}' on {date_str} from {start_time_str} to {end_time_str} by {session.get('fullname', 'N/A')} ({session['user_email']}) for Course: {course}, is awaiting your approval."
            body_html = f"""
                <html>
                    <body>
                        <p>A new booking for venue '<strong>{venue_name}</strong>' on <strong>{date_str}</strong> from <strong>{start_time_str}</strong> to <strong>{end_time_str}</strong> by <strong>{session.get('fullname', 'N/A')}</strong> (<strong>{session['user_email']}</strong>) is awaiting your approval.</p>
                        <p><strong>Purpose:</strong> {purpose}</p>
                        <p><strong>Course:</strong> {course}</p>
                        <p>Please log into the admin dashboard to review and approve the booking.</p>
                    </body>
                </html>
            """
            send_email_notification(admin_email, subject, body_plain, body_html)

        return jsonify({"message": "Booking request submitted successfully and is pending approval!"}), 201

    except Exception as e:
        print(f"Error creating booking: {e}")
        return jsonify({"error": f"Failed to create booking: {str(e)}"}), 500

@app.route('/api/bookings', methods=['GET'])
def get_bookings():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401

    try:
        bookings_ref = db.collection('artifacts').document(APP_ID).collection('bookings')
        query = bookings_ref

        # Apply filters from query parameters
        venue_filter = request.args.get('venue')
        status_filter = request.args.get('status')
        start_date_filter = request.args.get('start_date')
        end_date_filter = request.args.get('end_date')
        search_term = request.args.get('search')
        email_filter = request.args.get('email') # New filter for specific user email

        if venue_filter:
            query = query.where('venue_name', '==', venue_filter)
        if status_filter:
            query = query.where('status', '==', status_filter)

        # If email filter is provided, use it (for student's own bookings)
        if email_filter:
            query = query.where('booked_by_email', '==', email_filter)
        # Admins see all bookings, otherwise if no specific email filter,
        # users only see their own. This ensures admin can still see all,
        # but student can only see their own if no email filter provided
        # or if it's their own email.
        elif session.get('user_role') != 'admin':
            query = query.where('booked_by_uid', '==', session['user_id'])

        bookings_docs = query.get() # Fetch documents first without order_by for flexibility

        bookings_list = []
        for doc in bookings_docs:
            booking = doc.to_dict()
            booking['id'] = doc.id # Add document ID

            # Convert Firestore Timestamps and datetimes to string for JSON
            if 'start_datetime' in booking and booking['start_datetime']:
                # Changed: Only check for datetime.datetime type
                if isinstance(booking['start_datetime'], datetime.datetime):
                    booking['start_datetime'] = booking['start_datetime'].isoformat()
            if 'end_datetime' in booking and booking['end_datetime']:
                # Changed: Only check for datetime.datetime type
                if isinstance(booking['end_datetime'], datetime.datetime):
                    booking['end_datetime'] = booking['end_datetime'].isoformat()
            if 'requested_on' in booking and booking['requested_on']:
                # Changed: Only check for datetime.datetime type
                if isinstance(booking['requested_on'], datetime.datetime):
                    booking['requested_on'] = booking['requested_on'].isoformat()

            # Apply date range filter in Python (Firestore range queries on timestamps are complex with other filters)
            if start_date_filter and booking['date'] < start_date_filter:
                continue
            if end_date_filter and booking['date'] > end_date_filter:
                continue

            # Apply search filter in Python (Firestore text search is limited)
            if search_term:
                search_term_lower = search_term.lower()
                if not (search_term_lower in booking.get('purpose', '').lower() or
                        search_term_lower in booking.get('booked_by_fullname', '').lower() or
                        search_term_lower in booking.get('booked_by_matric_no', '').lower() or
                        search_term_lower in booking.get('venue_name', '').lower() or
                        search_term_lower in booking.get('course', '').lower()): # Include course in search
                    continue

            bookings_list.append(booking)

        # Sort the results in Python after filtering
        bookings_list.sort(key=lambda x: (x['date'], x['start_time']))

        return jsonify({"bookings": bookings_list}), 200 # Wrap in "bookings" key
    except Exception as e:
        print(f"Failed to fetch bookings: {str(e)}")
        return jsonify({"error": f"Failed to fetch bookings: {str(e)}"}), 500

@app.route('/api/bookings/<booking_id>/status', methods=['PUT'])
def update_booking_status(booking_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can update booking status."}), 403

    data = request.get_json()
    new_status = data.get('status')
    if not new_status or new_status not in ['approved', 'rejected', 'pending']:
        return jsonify({"error": "Invalid status provided. Must be 'approved', 'rejected', or 'pending'."}), 400

    booking_ref = db.collection('artifacts').document(APP_ID).collection('bookings').document(booking_id)
    try:
        booking_doc = booking_ref.get()
        if not booking_doc.exists:
            return jsonify({"error": "Booking not found."}), 404

        current_booking_data = booking_doc.to_dict()
        current_status = current_booking_data.get('status')

        # Only update if status is actually changing to avoid sending duplicate emails
        if current_status != new_status:
            booking_ref.update({'status': new_status, 'last_updated': firestore.SERVER_TIMESTAMP})

            # Send email notification
            recipient_email = current_booking_data.get('booked_by_email')
            recipient_name = current_booking_data.get('booked_by_fullname')
            if recipient_email and (new_status == 'approved' or new_status == 'rejected'): # Only send for final decisions
                email_sent_success = send_booking_notification_email(
                    recipient_email,
                    recipient_name,
                    current_booking_data, # Pass the full booking data
                    new_status
                )
                # Optionally update 'email_sent' field in Firestore
                booking_ref.update({'email_sent': email_sent_success})

            # --- NEW: Add a notification to the user's notifications collection ---
            if recipient_email and current_booking_data.get('booked_by_uid'):
                notification_message = ""
                if new_status == 'approved':
                    notification_message = f"Your booking for {current_booking_data.get('course', current_booking_data['purpose'])} in {current_booking_data['venue_name']} on {current_booking_data['date']} has been APPROVED!"
                elif new_status == 'rejected':
                    notification_message = f"Your booking for {current_booking_data.get('course', current_booking_data['purpose'])} in {current_booking_data['venue_name']} on {current_booking_data['date']} has been REJECTED. Reason: {current_booking_data.get('rejection_reason', 'N/A')}."
                
                if notification_message:
                    user_notifications_ref = db.collection('artifacts').document(APP_ID).collection('users').document(current_booking_data['booked_by_uid']).collection('notifications')
                    user_notifications_ref.add({
                        'type': 'booking_status_update',
                        'booking_id': booking_id,
                        'message': notification_message,
                        'timestamp': firestore.SERVER_TIMESTAMP,
                        'is_read': False, # New notifications are unread by default
                        'status': new_status # Store status for icon/color
                    })
                    print(f"Notification added for user {current_booking_data['booked_by_uid']}: {notification_message}")


            return jsonify({"message": f"Booking {booking_id} status updated to {new_status}."}), 200
        else:
            return jsonify({"message": f"Booking {booking_id} status is already {new_status}. No change made."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to update booking status: {str(e)}"}), 500

# --- API Endpoints for Users (Admin Only) ---
@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can view users."}), 403
    try:
        users = db.collection('artifacts').document(APP_ID).collection('users').get()
        users_list = []
        for doc in users:
            user_data = doc.to_dict()
            # Filter out staff users from being explicitly listed if desired
            # For now, we allow admin to see all roles, but 'staff' cannot register
            # if user_data.get('role') == 'staff':
            #    continue # Uncomment to hide staff from admin view

            # Exclude sensitive info like password hash if it were ever stored directly
            # and convert Timestamps
            if 'created_at' in user_data and user_data['created_at']:
                # Changed: Only check for datetime.datetime type
                if isinstance(user_data['created_at'], datetime.datetime):
                    user_data['created_at'] = user_data['created_at'].isoformat()
            users_list.append({
                "id": doc.id, # Use 'id' for consistency with frontend
                "email": user_data.get('email'),
                "fullname": user_data.get('fullname'),
                "role": user_data.get('role'),
                "matric_no": user_data.get('matric_no'), # Include matric_no
                "profile_picture_url": user_data.get('profile_picture_url', ''), # Include profile picture URL
                "status": 'approved' if user_data.get('is_approved') else 'pending', # Map is_approved to status string
                "registered_on": user_data.get('created_at')
            })
        return jsonify({"users": users_list}), 200 # Wrap in "users" key
    except Exception as e:
        return jsonify({"error": f"Failed to fetch users: {str(e)}"}), 500

@app.route('/api/users/<uid>/approve', methods=['POST'])
def approve_user(uid):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can approve users."}), 403
    try:
        user_ref = db.collection('artifacts').document(APP_ID).collection('users').document(uid)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({"error": "User not found."}), 404

        user_ref.update({'is_approved': True, 'last_updated': firestore.SERVER_TIMESTAMP})

        # Notify user of approval
        user_data = user_doc.to_dict()
        user_email = user_data.get('email')
        fullname = user_data.get('fullname', 'User')
        if user_email:
            subject = "Your Account Has Been Approved!"
            body_plain = f"Dear {fullname},\n\nGood news! Your venue booking system account has been approved by the administrator. You can now log in and start booking venues."
            body_html = f"""
                <html>
                    <body>
                        <p>Dear {fullname},</p>
                        <p>Good news! Your venue booking system account has been approved by the administrator. You can now log in and start booking venues.</p>
                        <p>Click <a href="{os.environ.get('BASE_URL', 'http://127.0.0.1:5000')}/login">here</a> to log in.</p>
                    </body>
                </html>
            """
            send_email_notification(user_email, subject, body_plain, body_html)

        # --- NEW: Add a notification to the user's notifications collection for account approval ---
        user_notifications_ref = db.collection('artifacts').document(APP_ID).collection('users').document(uid).collection('notifications')
        user_notifications_ref.add({
            'type': 'account_status',
            'message': f"Your account has been APPROVED! You can now log in and book venues.",
            'timestamp': firestore.SERVER_TIMESTAMP,
            'is_read': False, # New notifications are unread by default
            'status': 'approved'
        })
        print(f"Notification added for user {uid}: Account approved.")

        return jsonify({"message": f"User {uid} approved successfully and notified!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to approve user: {str(e)}"}), 500

@app.route('/api/users/<uid>/reject', methods=['POST'])
def reject_user(uid):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can reject users."}), 403
    try:
        user_ref = db.collection('artifacts').document(APP_ID).collection('users').document(uid)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({"error": "User not found."}), 404

        user_ref.update({'is_approved': False, 'last_updated': firestore.SERVER_TIMESTAMP}) # Set to False for rejection/deactivation

        # Notify user of rejection/deactivation
        user_data = user_doc.to_dict()
        user_email = user_data.get('email')
        fullname = user_data.get('fullname', 'User')
        if user_email:
            subject = "Your Account Status Update"
            body_plain = f"Dear {fullname},\n\nYour venue booking system account status has been updated. Please contact the administrator for more details."
            body_html = f"""
                <html>
                    <body>
                        <p>Dear {fullname},</p>
                        <p>Your venue booking system account status has been updated. Please contact the administrator for more details.</p>
                    </body>
                </html>
            """
            send_email_notification(user_email, subject, body_plain, body_html)

        # --- NEW: Add a notification to the user's notifications collection for account rejection ---
        user_notifications_ref = db.collection('artifacts').document(APP_ID).collection('users').document(uid).collection('notifications')
        user_notifications_ref.add({
            'type': 'account_status',
            'message': f"Your account status has been updated to REJECTED. Please contact administrator for details.",
            'timestamp': firestore.SERVER_TIMESTAMP,
            'is_read': False, # New notifications are unread by default
            'status': 'rejected'
        })
        print(f"Notification added for user {uid}: Account rejected.")

        return jsonify({"message": f"User {uid} status updated (rejected/deactivated) and notified!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to update user status: {str(e)}"}), 500


# --- API Endpoints for Venues ---
@app.route('/api/venues', methods=['GET'])
def get_venues():
    try:
        venues_ref = db.collection('artifacts').document(APP_ID).collection('venues')
        venues_docs = venues_ref.get()
        venues_list = []
        for doc in venues_docs:
            venue_data = doc.to_dict()
            venue_data['id'] = doc.id # Include document ID
            venues_list.append(venue_data)
        return jsonify({"venues": venues_list}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch venues: {str(e)}"}), 500

@app.route('/api/venues', methods=['POST'])
def add_venue():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can add venues."}), 403
    data = request.get_json()
    name = data.get('name')
    capacity = data.get('capacity')
    amenities = data.get('amenities') # Can be a string or list

    if not name or not capacity:
        return jsonify({"error": "Venue name and capacity are required."}), 400
    if not isinstance(capacity, int) or capacity <= 0:
        return jsonify({"error": "Capacity must be a positive integer."}), 400

    # Ensure amenities is stored as a list
    if isinstance(amenities, str):
        amenities = [a.strip() for a in amenities.split(',') if a.strip()]
    elif not isinstance(amenities, list):
        amenities = []

    try:
        # Check if venue name already exists
        existing_venue = db.collection('artifacts').document(APP_ID).collection('venues').where('name', '==', name).limit(1).get()
        if existing_venue:
            return jsonify({"error": "Venue with this name already exists."}), 409

        venue_id = str(uuid.uuid4())
        db.collection('artifacts').document(APP_ID).collection('venues').document(venue_id).set({
            'name': name,
            'capacity': capacity,
            'amenities': amenities,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({"message": "Venue added successfully!", "id": venue_id}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to add venue: {str(e)}"}), 500

@app.route('/api/venues/<venue_id>', methods=['PUT'])
def update_venue(venue_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can update venues."}), 403
    data = request.get_json()
    name = data.get('name')
    capacity = data.get('capacity')
    amenities = data.get('amenities')

    if not name or not capacity:
        return jsonify({"error": "Venue name and capacity are required."}), 400
    if not isinstance(capacity, int) or capacity <= 0:
        return jsonify({"error": "Capacity must be a positive integer."}), 400

    if isinstance(amenities, str):
        amenities = [a.strip() for a in amenities.split(',') if a.strip()]
    elif not isinstance(amenities, list):
        amenities = []

    venue_ref = db.collection('artifacts').document(APP_ID).collection('venues').document(venue_id)
    try:
        venue_doc = venue_ref.get()
        if not venue_doc.exists:
            return jsonify({"error": "Venue not found."}), 404

        # Check for duplicate name if name is changed
        if venue_doc.to_dict().get('name') != name:
            existing_venue = db.collection('artifacts').document(APP_ID).collection('venues').where('name', '==', name).limit(1).get()
            if existing_venue:
                return jsonify({"error": "Venue with this name already exists."}), 409

        venue_ref.update({
            'name': name,
            'capacity': capacity,
            'amenities': amenities,
            'last_updated': firestore.SERVER_TIMESTAMP
        })
        return jsonify({"message": "Venue updated successfully!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to update venue: {str(e)}"}), 500

@app.route('/api/venues/<venue_id>', methods=['DELETE'])
def delete_venue(venue_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can delete venues."}), 403
    try:
        db.collection('artifacts').document(APP_ID).collection('venues').document(venue_id).delete()
        return jsonify({"message": "Venue deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to delete venue: {str(e)}"}), 500


# --- Site-wide Notice Endpoints ---
@app.route('/api/notice', methods=['GET'])
def get_notice():
    try:
        notice_doc_ref = db.collection('artifacts').document(APP_ID).collection('config').document('notice')
        notice_doc = notice_doc_ref.get()
        if notice_doc.exists:
            return jsonify(notice_doc.to_dict()), 200
        else:
            return jsonify({"message": "No notice set yet.", "content": ""}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch notice: {str(e)}"}), 500

@app.route('/api/notice', methods=['PUT']) # Changed endpoint to /api/notice
def update_notice():
    """Allows admin to update the site-wide notice."""
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can update notices."}), 403

    data = request.get_json()
    new_content = data.get('content')

    if new_content is None:
        return jsonify({"error": "Notice content is required."}), 400

    notice_doc_ref = db.collection('artifacts').document(APP_ID).collection('config').document('notice')
    try:
        notice_doc_ref.set({'content': new_content, 'last_updated': firestore.SERVER_TIMESTAMP})
        return jsonify({"message": "Notice updated successfully!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to update notice: {str(e)}"}), 500

# --- NEW: Notifications Endpoint ---
@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in to view notifications."}), 401

    user_uid = session['user_id']
    notifications_list = []
    
    try:
        # 1. Fetch site-wide notice
        notice_doc_ref = db.collection('artifacts').document(APP_ID).collection('config').document('notice')
        notice_doc = notice_doc_ref.get()
        if notice_doc.exists:
            notice_data = notice_doc.to_dict()
            if notice_data.get('content'):
                notifications_list.append({
                    'id': 'site-notice',
                    'type': 'site_notice',
                    'message': f"Site Notice: {notice_data['content']}",
                    'timestamp': notice_data.get('last_updated', firestore.SERVER_TIMESTAMP).isoformat(),
                    'status': 'info', # Custom status for styling
                    'is_read': True # Site notices are always considered read by default
                })

        # 2. Fetch user-specific booking notifications
        user_notifications_ref = db.collection('artifacts').document(APP_ID).collection('users').document(user_uid).collection('notifications')
        
        # Order by timestamp descending to get most recent first
        user_notification_docs = user_notifications_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(20).get() # Limit to last 20 notifications
        
        for doc in user_notification_docs:
            notification = doc.to_dict()
            notification['id'] = doc.id
            if 'timestamp' in notification and notification['timestamp']:
                # Changed: Only check for datetime.datetime type
                if isinstance(notification['timestamp'], datetime.datetime):
                    notification['timestamp'] = notification['timestamp'].isoformat()
            
            # Add a default status if not present (e.g., 'info')
            if 'status' not in notification:
                notification['status'] = 'info' 
            
            # Ensure 'is_read' field exists, default to False if not present
            if 'is_read' not in notification:
                notification['is_read'] = False

            notifications_list.append(notification)
        
        # Sort all notifications (site notice + user notifications) by timestamp descending
        notifications_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return jsonify({"notifications": notifications_list}), 200

    except Exception as e:
        print(f"Error fetching notifications for user {user_uid}: {e}")
        return jsonify({"error": f"Failed to fetch notifications: {str(e)}"}), 500

@app.route('/api/notifications/<notification_id>/mark_read', methods=['PUT'])
def mark_notification_read(notification_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401
    
    user_uid = session['user_id']
    notification_ref = db.collection('artifacts').document(APP_ID).collection('users').document(user_uid).collection('notifications').document(notification_id)

    try:
        notification_doc = notification_ref.get()
        if not notification_doc.exists:
            return jsonify({"error": "Notification not found."}), 404
        
        notification_ref.update({'is_read': True})
        return jsonify({"message": "Notification marked as read."}), 200
    except Exception as e:
        print(f"Error marking notification {notification_id} as read: {e}")
        return jsonify({"error": f"Failed to mark notification as read: {str(e)}"}), 500

# --- Report Generation Logic ---
def generate_report_data(report_type, start_date=None, end_date=None, venue_id=None, user_role=None):
    try:
        bookings_ref = db.collection('artifacts').document(APP_ID).collection('bookings')
        users_ref = db.collection('artifacts').document(APP_ID).collection('users')
        venues_ref = db.collection('artifacts').document(APP_ID).collection('venues')

        all_bookings = []
        for doc in bookings_ref.get():
            booking = doc.to_dict()
            booking['id'] = doc.id
            # Convert Firestore Timestamp to datetime objects and make them UTC-aware for consistency
            # Changed: Only check for datetime.datetime type
            if isinstance(booking.get('start_datetime'), datetime.datetime):
                # Ensure it's timezone-aware
                if booking['start_datetime'].tzinfo is None:
                    booking['start_datetime'] = pytz.utc.localize(booking['start_datetime'])
                else:
                    booking['start_datetime'] = booking['start_datetime'].astimezone(pytz.utc)

            # Changed: Only check for datetime.datetime type
            if isinstance(booking.get('end_datetime'), datetime.datetime):
                # Ensure it's timezone-aware
                if booking['end_datetime'].tzinfo is None:
                    booking['end_datetime'] = pytz.utc.localize(booking['end_datetime'])
                else:
                    booking['end_datetime'] = booking['end_datetime'].astimezone(pytz.utc)
                
            all_bookings.append(booking)

        # Filter bookings by date range
        filtered_bookings = []
        for booking in all_bookings:
            # Ensure booking['date'] is treated as a string 'YYYY-MM-DD' for comparison
            # If it's already a datetime object, convert it to string first for consistency
            booking_date_str = booking['date']
            # Assuming 'date' is already a 'YYYY-MM-DD' string from client
            
            booking_date = datetime.datetime.strptime(booking_date_str, "%Y-%m-%d").date()

            if start_date and booking_date < datetime.datetime.strptime(start_date, "%Y-%m-%d").date():
                continue
            if end_date and booking_date > datetime.datetime.strptime(end_date, "%Y-%m-%d").date():
                continue

            if venue_id and booking.get('venue_id') != venue_id:
                continue

            filtered_bookings.append(booking)

        if report_type == 'venue_utilization':
            venue_data = {}
            for doc in venues_ref.get():
                venue = doc.to_dict()
                venue_data[doc.id] = {'name': venue.get('name'), 'capacity': venue.get('capacity'), 'total_bookings': 0, 'total_hours_booked': 0.0}

            for booking in filtered_bookings:
                if booking['status'] == 'approved' and booking['venue_id'] in venue_data:
                    venue_data[booking['venue_id']]['total_bookings'] += 1
                    # Calculate duration in hours
                    # Ensure start_datetime and end_datetime are timezone-aware here
                    duration = (booking['end_datetime'] - booking['start_datetime']).total_seconds() / 3600
                    venue_data[booking['venue_id']]['total_hours_booked'] += duration

            # Calculate utilization percentage (simplistic, assuming 24/7 availability for calculation base)
            # A more accurate utilization would require defined operational hours for each venue.
            report_output = []
            total_days_in_period = 0
            if start_date and end_date:
                s_date = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
                e_date = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
                total_days_in_period = (e_date - s_date).days + 1

            for v_id, data in venue_data.items():
                # Assuming max 24 hours available per day for a simple calculation
                # For more realism, fetch venue's actual available hours per day
                total_possible_hours = total_days_in_period * 24 if total_days_in_period > 0 else 0

                utilization_percentage = (data['total_hours_booked'] / total_possible_hours * 100) if total_possible_hours > 0 else 0

                report_output.append({
                    'venue_id': v_id,
                    'venue_name': data['name'],
                    'capacity': data['capacity'],
                    'total_bookings': data['total_bookings'],
                    'total_hours_booked': data['total_hours_booked'],
                    'utilization_percentage': utilization_percentage
                })
            return report_output

        elif report_type == 'booking_summary':
            summary = {'pending': 0, 'approved': 0, 'rejected': 0}
            for booking in filtered_bookings:
                status = booking.get('status', 'pending')
                if status in summary:
                    summary[status] += 1
            return summary

        elif report_type == 'user_activity':
            user_activity = {}
            all_users = {doc.id: doc.to_dict() for doc in users_ref.get()}

            for uid, user_data in all_users.items():
                if user_role and user_data.get('role') != user_role:
                    continue
                user_activity[uid] = {
                    'fullname': user_data.get('fullname', 'N/A'),
                    'email': user_data.get('email', 'N/A'),
                    'role': user_data.get('role', 'N/A'),
                    'total_bookings': 0,
                    'approved_bookings': 0,
                    'pending_bookings': 0,
                    'rejected_bookings': 0
                }

            for booking in filtered_bookings:
                booked_by_uid = booking.get('booked_by_uid')
                if booked_by_uid in user_activity:
                    user_activity[booked_by_uid]['total_bookings'] += 1
                    status = booking.get('status', 'pending')
                    if status == 'approved':
                        user_activity[booked_by_uid]['approved_bookings'] += 1
                    elif status == 'pending':
                        user_activity[booked_by_uid]['pending_bookings'] += 1
                    elif status == 'rejected':
                        user_activity[booked_by_uid]['rejected_bookings'] += 1

            return list(user_activity.values()) # Convert dictionary to list of values

        else:
            return {"error": "Invalid report type."}

    except Exception as e:
        print(f"Error generating report data: {e}")
        return {"error": f"Failed to generate report data: {str(e)}"}

def generate_pdf_report(report_type, report_data, start_date=None, end_date=None):
    """Generates a PDF report based on type and data."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []

    # Title
    report_title = {
        'booking_summary': "Booking Summary Report",
        'venue_utilization': "Venue Utilization Report",
        'user_activity': "User Activity Report"
    }.get(report_type, "General Report")

    Story.append(Paragraph(f"<b>{report_title}</b>", styles['h1']))
    Story.append(Spacer(1, 0.2 * inch))

    # Date range (if applicable)
    if start_date and end_date:
        Story.append(Paragraph(f"<b>Date Range:</b> {start_date} to {end_date}", styles['Normal']))
        Story.append(Spacer(1, 0.1 * inch))
    elif start_date:
        Story.append(Paragraph(f"<b>Start Date:</b> {start_date}", styles['Normal']))
        Story.append(Spacer(1, 0.1 * inch))
    elif end_date:
        Story.append(Paragraph(f"<b>End Date:</b> {end_date}", styles['Normal']))
        Story.append(Spacer(1, 0.1 * inch))


    # Table content
    data_for_table = []
    headers = []

    if report_type == 'booking_summary':
        headers = ['Status', 'Count']
        data_for_table.append(headers)
        data_for_table.append(['Approved', report_data.get('approved', 0)])
        data_for_table.append(['Pending', report_data.get('pending', 0)])
        data_for_table.append(['Rejected', report_data.get('rejected', 0)])
    elif report_type == 'venue_utilization':
        headers = ['Venue Name', 'Capacity', 'Total Bookings', 'Total Hours Booked', 'Utilization (%)']
        data_for_table.append(headers)
        for row in report_data:
            data_for_table.append([
                row.get('venue_name'),
                row.get('capacity'),
                row.get('total_bookings'),
                f"{row.get('total_hours_booked'):.2f}",
                f"{row.get('utilization_percentage'):.2f}%"
            ])
    elif report_type == 'user_activity':
        headers = ['Full Name', 'Email', 'Role', 'Total Bookings', 'Approved', 'Pending', 'Rejected']
        data_for_table.append(headers)
        for row in report_data:
            data_for_table.append([
                row.get('fullname'),
                row.get('email'),
                row.get('role'),
                row.get('total_bookings'),
                row.get('approved_bookings'),
                row.get('pending_bookings'),
                row.get('rejected_bookings')
            ])
    else:
        Story.append(Paragraph("No data to display for this report type.", styles['Normal']))
        doc.build(Story)
        buffer.seek(0)
        return buffer.getvalue()

    if not data_for_table:
        Story.append(Paragraph("No data available for this report.", styles['Normal']))
        doc.build(Story)
        buffer.seek(0)
        return buffer.getvalue()

    table = Table(data_for_table)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey), # Header background
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke), # Header text color
        ('ALIGN', (0,0), (-1,-1), 'CENTER'), # Center align all cells
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'), # Header font
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige), # Alternating row color
        ('GRID', (0,0), (-1,-1), 1, colors.black), # All borders
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'), # Vertical alignment
    ]))

    Story.append(table)
    doc.build(Story)
    buffer.seek(0)
    return buffer.getvalue()


@app.route('/api/reports', methods=['GET'])
def get_reports():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can generate reports."}), 403

    report_type = request.args.get('report_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    venue_id = request.args.get('venue_id')
    user_role = request.args.get('user_role')

    if not report_type:
        return jsonify({"error": "Report type is required."}), 400

    report_data = generate_report_data(report_type, start_date, end_date, venue_id, user_role)

    if "error" in report_data:
        return jsonify(report_data), 500

    return jsonify({"report_type": report_type, "data": report_data}), 200

@app.route('/api/reports/export', methods=['GET'])
def export_reports():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({"error": "Unauthorized. Only administrators can export reports."}), 403

    report_type = request.args.get('report_type')
    file_format = request.args.get('format')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    venue_id = request.args.get('venue_id')
    user_role = request.args.get('user_role')

    if not report_type or not file_format:
        return jsonify({"error": "Report type and format are required."}), 400

    report_data = generate_report_data(report_type, start_date, end_date, venue_id, user_role)

    if "error" in report_data:
        return jsonify(report_data), 500

    if file_format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)

        if report_type == 'venue_utilization':
            headers = ['Venue Name', 'Capacity', 'Total Bookings', 'Total Hours Booked', 'Utilization (%)']
            writer.writerow(headers)
            for row in report_data:
                writer.writerow([
                    row.get('venue_name'),
                    row.get('capacity'),
                    row.get('total_bookings'),
                    f"{row.get('total_hours_booked'):.2f}",
                    f"{row.get('utilization_percentage'):.2f}%"
                ])
        elif report_type == 'booking_summary':
            headers = ['Status', 'Count']
            writer.writerow(headers)
            for status, count in report_data.items():
                writer.writerow([status.title(), count])
        elif report_type == 'user_activity':
            headers = ['Full Name', 'Email', 'Role', 'Total Bookings', 'Approved Bookings', 'Pending Bookings', 'Rejected Bookings']
            writer.writerow(headers)
            for row in report_data:
                writer.writerow([
                    row.get('fullname'),
                    row.get('email'),
                    row.get('role'),
                    row.get('total_bookings'),
                    row.get('approved_bookings'),
                    row.get('pending_bookings'),
                    row.get('rejected_bookings')
                ])
        else:
            return jsonify({"error": "Unsupported report type for CSV export."}), 400

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename={report_type}_report.csv"}
        )
    elif file_format == 'pdf':
        pdf_bytes = generate_pdf_report(report_type, report_data, start_date, end_date)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment;filename={report_type}_report.pdf"}
        )
    else:
        return jsonify({"error": "Invalid file format. Supported formats: csv, pdf."}), 400


if __name__ == '__main__':
    # For local development, set a dummy ADMIN_EMAIL
    if os.environ.get('FLASK_ENV') == 'development' and not os.environ.get('ADMIN_EMAIL'):
        os.environ['ADMIN_EMAIL'] = 'your_admin_email@example.com' # CHANGE THIS IN PRODUCTION!
        print("Using dummy ADMIN_EMAIL for development.")

    app.run(debug=True, host='0.0.0.0')
