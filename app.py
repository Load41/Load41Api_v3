from flask import Flask, jsonify, request
import os
import json
import logging
from Live_Token import Live_Token
from truckstop_token import Truckstop_Token
from direct_freight_token import Direct_Token
from twilio.rest import Client
import requests
from werkzeug.exceptions import BadRequest
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
from functools import wraps
import random
import tempfile
from datetime import timedelta
import re
import psycopg2

import uuid
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import SQLAlchemyError
import phonenumbers
from phonenumbers import NumberParseException
from twilio.base.exceptions import TwilioRestException

from flask_socketio import SocketIO
from flask_cors import CORS, cross_origin
import socketio

from dotenv import load_dotenv
import os

app = Flask(__name__)
# default config
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins="*")
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

# logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.DEBUG)





# Allow CORS for your frontend's origin
# CORS(app, resources={r"/socket.io/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000", "*"]}})
# CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
# CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)
# CORS(app, supports_credentials=True, origins=["https://load41.com"])

@app.route('/wtf')
def index(): 
    return "WebSocket Server Running!"

@socketio.on('connect')
def handle_connect():
    print("Client connected")


    

app.config["SECRET_KEY"] = "fgg67768rf#$$$$$33334rfg6666$%@!$ffff"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "postgresql://postgres:password@localhost:5432/postgres"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)


# Twilio configuration
load_dotenv()  # Load the environment variables from .env file
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

# Initialize the Twilio client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Credentials for the APIs
DAT_CREDENTIALS = {
    "username": "thomas@jakebrakelogistics.com",
    "username_organization": "adrian@jakebrakelogistics.com",
    "password_organization": "Sharmaboy@3456789",
}

DIRECT_CREDENTIALS = {
    "username": "thomas@jakebrakelogistics.com", #thomas@jakebrakelogistics.com
    "password": "Flyboy69y2",  #Flyboy69y2
    "api_token": "5b3a9a184bfd9a750b6ba4741497ac7698300fd4", #5b3a9a184bfd9a750b6ba4741497ac7698300fd4
}

TRUCKSTOP_CREDENTIALS = {
    "client_id": "846C0339-8B12-483A-A395-016FAF658A4E", #  846C0339-8B12-483A-A395-016FAF658A4E
    "client_secret": "49356486-F88C-4989-B9C3-F5541E74BF50", #  49356486-F88C-4989-B9C3-F5541E74BF50
    "username": "booknow@jakebrakelogistics.com", #  booknow@jakebrakelogistics.com
    "password": "Flyboy69y2k@", #  Flyboy69y2k@
}

# TruckerPath Token (static as provided)
TRUCKERPATH_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMzVhMWZjMjQxODBiY2NmMTcwY2EzNWVhZGMwMjdjOSIsImp0aSI6Ik1EZ3hZekExTldZdE5HUmxaUzAwTXpobUxXSTBNMk10TW1Oak9UWTNNVEpsWm1WaCIsImV4cCI6MTczMDU5MjAwMH0.NcEgDpg8wai0pnsrleGnywlpIeZEjL2pbElSnJhfsKF5OAQJs6ZLGodH-F1D8zzK5OBPcMruH_WNe7TAgV3S1ZxEt8-Flc2opDPmp2yKpUIrYjLV2wYYg_Q6_7SH_pZLPo7lOrMOfHJSG7mEf8uX3__KgjoAqfQ9oAg78SeuH2gUNeMM8r9DfyzWxSq_VaqW4yXGnqGf9tuilaN_I2S1mgK5spPZNmqVE9ebMwOn7qLHlnKSRgpOEmi3ATOBhNAAEVm72HnfyD4fE9VS72uTACFdjSjkuiDTL8LvoFkZ0lPvnfqAV6_5y9Di3wIAWdNK4qsCAxyD3cEjbtbI1J5trg"

# Error messages
INVALID_FORMAT_MSG = "Invalid data format. Expected a JSON object."
NOT_FOUND_MSG = "TrackersInfo entry not found."
UNAUTHORIZED_MSG = "Unauthorized to perform this action."
DATABASE_ERROR_MSG = "A database error occurred."
INVALID_ID_MSG = "Invalid ID format."


# Models
class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=True)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    username = db.Column(db.String(50))
    group_name = db.Column(db.String(50))
    user_type = db.Column(db.String(50))
    role = db.Column(db.String(50))
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.LargeBinary, nullable=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)

    def check_password(self, password):
        # Implement password check logic, e.g., hash comparison
        return self.password == password

class ActiveTrackers(db.Model):
    __tablename__ = "active_trackers"

    id = db.Column(db.Integer, primary_key=True)
    #tracker_id = db.Column(db.Integer, db.ForeignKey("trackers_info.id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Link to user
    trackingId = db.Column(db.Integer, db.ForeignKey('trackers_info.trackingId'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="ACTIVE")
    createdAt = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    tracker = db.relationship("TrackersInfo", backref="active_tracker")
    user = db.relationship("Users", backref="active_tracker")  # Optional: backref to the Users table

    def __repr__(self):
        return f"<ActiveTrackers {self.id}>"


class MobileUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)


class TrackersInfo(db.Model):
    __tablename__ = "trackers_info"

    id = db.Column(db.Integer, unique=True, primary_key=True)
    driverPhoneNumber = db.Column(db.String(20))
    email = db.Column(db.String(120))
    comment = db.Column(db.String, nullable=True)
    datetimes = db.Column(db.DateTime, nullable=True)
    dispatcher = db.Column(db.String(50), nullable=True)
    driver = db.Column(db.String(50), nullable=True)
    brokerName = db.Column(db.String(50), nullable=True)
    deliveryProofPhotos = db.Column(db.JSON, nullable=True, default={})
    isDeleted = db.Column(db.Boolean, default=False)
    locationLogs = db.Column(db.JSON, nullable=True, default={})
    shippingData = db.Column(db.JSON, nullable=True, default={})
    equipmentType = db.Column(db.String(50), nullable=True)
    latestAvailability = db.Column(db.String(50), nullable=True)
    loadId = db.Column(db.Integer, nullable=True)  # Nullable if this can be empty
    trackingId = db.Column(
        db.Integer, unique=True, nullable=True
    )  # Ensure unique tracking ID
    price = db.Column(
        db.Numeric(10, 2), nullable=True
    )  # Specify precision and scale for numeric
    loadStatus = db.Column(db.String(50), nullable=True)
    createdAt = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updatedAt = db.Column(
        db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    # Foreign key linking to the Users table
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    def __repr__(self):
        return f"<TrackersInfo {self.id}>"

    def to_dict(self):
        return {
            "id": self.id,
            "driverPhoneNumber": self.driverPhoneNumber,
            "email": self.email,
            "comment": self.comment,
            "datetimes": self.datetimes,
            "dispatcher": self.dispatcher,
            "driver": self.driver,
            "brokerName": self.brokerName,
            "deliveryProofPhotos": self.deliveryProofPhotos,
            "isDeleted": self.isDeleted,
            "locationLogs": self.locationLogs,
            "shippingData": self.shippingData,
            "equipmentType": self.equipmentType,
            "latestAvailability": self.latestAvailability,
            "loadId": self.loadId,
            "trackingId": self.trackingId,
            "price": str(self.price),
            "loadStatus": self.loadStatus,
            "createdAt": self.createdAt,
            "updatedAt": self.updatedAt,
            "user_id": self.user_id,
        }

class UserDevices(db.Model):
    __tablename__ = "user_devices"
    id = db.Column(db.Integer, primary_key=True)
    device_token = db.Column(db.String(255), unique=True, nullable=False)
    trackingId = db.Column(db.Integer, nullable=False)


class Notifications(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    trackingId = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    createdAt = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class UsersDetails(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    data = db.Column(db.JSON)
    type = db.Column(db.String(50))


class UserLogins(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    device_info = db.Column(db.JSON)
    location = db.Column(db.String(100))


class Contact(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(120))
    message = db.Column(db.Text)


class Subscription(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    loads = db.Column(db.String(50))
    business = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    company = db.Column(db.String(100))
    date = db.Column(db.DateTime)


class CustomMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Add custom processing here
        print("Custom Middleware: Before Request")

        def custom_start_response(status, headers):
            # Modify response headers or status
            headers.append(("X-Custom-Header", "Value"))
            return start_response(status, headers)

        # Call the WSGI app and get the response
        response = self.app(environ, custom_start_response)

        # Add custom processing here
        print("Custom Middleware: After Request")

        return response


UPLOAD_FOLDER = "uploads/avatars"  # Directory where avatars will be stored
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Helper function to check if the file extension is allowed
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Utility function to create a standard response
def create_response(status, data=None, message=""):
    response = {"status": status, "data": data if data else [], "message": message}
    return jsonify(response), status


# Utility Functions
def send_otp(phone_number, otp):
    # Twilio configuration
    account_sid = TWILIO_ACCOUNT_SID
    auth_token = TWILIO_AUTH_TOKEN
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=f"Your Load41 OTP code is {otp}",
        from_=TWILIO_PHONE_NUMBER,
        to=phone_number,
    )


def generate_otp():
    return str(random.randint(100000, 999999))


def generate_token(user_id):
    token = jwt.encode(
        {
            "sub": user_id,
            "exp": datetime.datetime.utcnow() + timedelta(days=1),  # Token expires in 1 day
            "iat": datetime.datetime.utcnow(),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return create_response(403, message="Token is missing!")

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = Users.query.get(data["sub"])

            if current_user is None:
                return create_response(404, message="User not found!")

        except jwt.ExpiredSignatureError:
            # Allow token refresh within a grace period (e.g., 10 minutes)
            token_data = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
            if datetime.datetime.utcnow() - datetime.utcfromtimestamp(
                token_data["exp"]
            ) < timedelta(minutes=10):
                # Grace period is valid, allow token refresh
                new_token = generate_token(token_data["sub"])
                return create_response(
                    401,
                    message="Token has expired, but can be refreshed!",
                    data={"new_token": new_token},
                )
            return create_response(
                401, message="Token has expired and cannot be refreshed!"
            )
        except jwt.InvalidTokenError:
            return create_response(403, message="Invalid token!")

        return f(current_user.id, *args, **kwargs)

    return decorated


def validate_email(email):
    """Validate email format."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False
    return True


def validate_phone_number(phone_number):
    """Validate phone number format."""
    if not re.match(r"^\+?[0-9]{7,15}$", phone_number):
        return False
    return True


# Helper function to validate integer fields
def validate_integer(value, field_name):
    try:
        return int(value) if value is not None else None
    except ValueError:
        raise ValueError(f"Invalid {field_name}: {value}")


# Base Route
@app.route("/")
def home():
    return "Welcome to the Load41 !"

# @app.route("/users/<int:user_id>", methods=["PUT"])
# @token_required
# def update_user(current_user_id, user_id):
#     # Ensure the user is authorized to update their profile
#     if current_user_id != user_id:
#         return create_response(403, message="Unauthorized to update this profile")

#     # Check if the request contains a file (FormData) or just JSON
#     if request.content_type.startswith('multipart/form-data'):
#         # Handling multipart/form-data
#         data = request.form  # Access form fields directly, no need to call to_dict()
#         file = request.files.get("file")  # Get the uploaded file if present
#     else:
#         # Handling application/json
#         data = request.get_json()
#         file = None

#     if not data and not file:
#         return create_response(400, message="No data provided")

#     # Find the user by ID
#     user = Users.query.get(user_id)
#     if not user:
#         return create_response(404, message="User not found")

#     try:
#         # Check for email uniqueness if provided
#         if "email" in data:
#             email = data["email"]
#             if not validate_email(email):
#                 return create_response(400, message="Invalid email format")
#             if Users.query.filter_by(email=email).first() and email != user.email:
#                 return create_response(400, message="Email already in use")
#             user.email = email

#         # Check for phone number uniqueness if provided
#         if "phone_number" in data:
#             phone_number = data["phone_number"]
#             if not validate_phone_number(phone_number):
#                 return create_response(400, message="Invalid phone number format")
#             if Users.query.filter_by(phone_number=phone_number).first() and phone_number != user.phone_number:
#                 return create_response(400, message="Phone number already in use")
#             user.phone_number = phone_number

#         # Update other fields
#         if "username" in data:
#             user.username = data["username"]

#         if "group_name" in data:
#             user.group_name = data["group_name"]

#         if "user_type" in data:
#             user.user_type = data["user_type"]

#         if "role" in data:
#             user.role = data["role"]

#         if "is_admin" in data:
#             user.is_admin = data["is_admin"]

#         if "first_name" in data:
#             user.first_name = data["first_name"]

#         if "last_name" in data:
#             user.last_name = data["last_name"]

#         # Handle avatar upload if a file is provided
#         if file:
#             if allowed_file(file.filename):
#                 # Read the file as binary and store it (or save it to disk as per your setup)
#                 user.avatar = file.read()
#             else:
#                 return create_response(400, message="Invalid file type. Allowed types are png, jpg, jpeg, gif.")

#         # If a new password is provided, update it
#         if "password" in data:
#             new_password = data["password"]
#             if len(new_password) < 6:  # Example password validation rule
#                 return create_response(400, message="Password must be at least 6 characters long")
#             user.password = new_password  # Ensure you hash the password in a real application

#         # Commit the changes to the database
#         db.session.commit()

#         return create_response(200, message="User details updated successfully")

#     except Exception as e:
#         app.logger.error(f"Unexpected error: {e}")
#         db.session.rollback()  # Rollback in case of error
#         return create_response(500, message="An unexpected error occurred", data={"error": str(e)})
@app.route("/users/<int:user_id>", methods=["PUT"])
@token_required
def update_user(current_user_id, user_id):
    if current_user_id != user_id:
        return create_response(403, message="Unauthorized to update this profile")

    data = request.get_json()

    user = Users.query.get(user_id)
    if not user:
        return create_response(404, message="User not found")

    try:
        # Ensure Boolean conversion for 'is_admin'
        if "is_admin" in data:
            user.is_admin = bool(data["is_admin"])

        # Update avatar URL (if provided) - Assuming it's a URL, not the binary file
        if "avatar_url" in data:
            user.avatar_url = data["avatar_url"]

        # Update other fields (email, phone_number, etc.) as needed
        if "email" in data:
            user.email = data["email"]
        if "phone_number" in data:
            user.phone_number = data["phone_number"]
        if "username" in data:
            user.username = data["username"]
        if "group_name" in data:
            user.group_name = data["group_name"]
        if "user_type" in data:
            user.user_type = data["user_type"]
        if "role" in data:
            user.role = data["role"]
        if "first_name" in data:
            user.first_name = data["first_name"]
        if "last_name" in data:
            user.last_name = data["last_name"]

        # Handle avatar file upload if present
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            user.avatar = file.read()  # Store file as binary (if you use binary storage)
        elif file:
            return create_response(400, message="Invalid file type. Allowed types are png, jpg, jpeg, gif.")

        # Handle password update (if provided)
        if "password" in data:
            new_password = data["password"]
            if len(new_password) < 6:
                return create_response(400, message="Password must be at least 6 characters long")
            user.password = new_password  # Ensure to hash the password in production!

        # Commit the changes to the database
        db.session.commit()

        return create_response(200, message="User details updated successfully")

    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        db.session.rollback()  # Rollback in case of an error
        return create_response(500, message="An unexpected error occurred", data={"error": str(e)})


@app.route('/delete-user/<int:user_id>', methods=['DELETE'])
@token_required  # Assuming you have token-based authentication
def delete_user(current_user_id, user_id):
    try:
        # Fetch the current user using the ID from the token (this depends on how you manage token authentication)
        current_user = Users.query.get(current_user_id)

        if not current_user:
            return jsonify({"message": "Current user not found"}), 404

        # Check if the current user has permission to delete the target user
        if not current_user.is_admin and current_user.id != user_id:
            return jsonify({"message": "Permission denied. You do not have the rights to delete this user."}), 403

        # Fetch the target user to delete
        user = Users.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Delete the user and commit the transaction
        db.session.delete(user)
        db.session.commit()

        return jsonify({"message": "User deleted successfully."}), 200

    except IntegrityError as e:
        # Handle integrity-related database issues (foreign key constraints, etc.)
        db.session.rollback()  # Rollback the transaction in case of an error
        app.logger.error(f"Database integrity error while deleting user {user_id}: {str(e)}")
        return jsonify({"message": "Could not delete user due to database integrity issues."}), 500

    except SQLAlchemyError as e:
        # Handle other SQLAlchemy-related errors
        db.session.rollback()
        app.logger.error(f"Database error while deleting user {user_id}: {str(e)}")
        return jsonify({"message": "An unexpected database error occurred."}), 500

    except Exception as e:
        # Handle any other unexpected exceptions
        app.logger.error(f"Unexpected error while deleting user {user_id}: {str(e)}")
        return jsonify({"message": "An unexpected error occurred.", "error": str(e)}), 500




# @app.route("/upload-avatar", methods=["POST"])
# @token_required
# def upload_avatar(user_id):
#     if "file" not in request.files:
#         return create_response(
#             400, message="No file provided", data={"message": "No file provided"}
#         )

#     file = request.files["file"]

#     if file.filename == "":
#         return create_response(400, message="No selected file")

#     if file and allowed_file(file.filename):
#         try:
#             filename = secure_filename(file.filename)
#             unique_filename = f"{uuid.uuid4().hex}_{filename}"

#             # Create the upload directory if it doesn't exist
#             if not os.path.exists(app.config["UPLOAD_FOLDER"]):
#                 os.makedirs(app.config["UPLOAD_FOLDER"])

#             file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
#             file.save(file_path)

#             # Create a URL for the avatar
#             file_url = (
#                 f"{request.host_url}{app.config['UPLOAD_FOLDER']}/{unique_filename}"
#             )

#             # Update the user's avatar_url in the database
#             user = Users.query.get(user_id)
#             if user:
#                 user.avatar_url = file_url
#                 db.session.commit()
#             else:
#                 return create_response(404, message="User not found")

#             return create_response(
#                 201, message="Avatar uploaded successfully", data={"url": file_url}
#             )

#         except Exception as e:
#             app.logger.error(f"Error uploading avatar: {e}")
#             db.session.rollback()  # Rollback in case of an error
#             return create_response(
#                 500, message="Error uploading file", data={"error": str(e)}
#             )
#     else:
#         return create_response(
#             400, message="Invalid file type. Allowed types are png, jpg, jpeg, gif."
#         )

@app.route("/upload-avatar", methods=["POST"])
@token_required
def upload_avatar(user_id):
    if "file" not in request.files:
        app.logger.error("No file provided in the request")
        return create_response(400, message="No file provided")

    file = request.files["file"]

    if file.filename == "":
        app.logger.error("No selected file")
        return create_response(400, message="No selected file")

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"

            # Create the upload directory if it doesn't exist
            if not os.path.exists(app.config["UPLOAD_FOLDER"]):
                os.makedirs(app.config["UPLOAD_FOLDER"])

            file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
            file.save(file_path)

            # Create a URL for the avatar
            file_url = f"{request.host_url}{app.config['UPLOAD_FOLDER']}/{unique_filename}"

            # Update the user's avatar_url in the database
            user = Users.query.get(user_id)
            if user:
                user.avatar_url = file_url  # Save the URL, not binary data
                db.session.commit()
            else:
                app.logger.error(f"User with ID {user_id} not found.")
                return create_response(404, message="User not found")

            return create_response(201, message="Avatar uploaded successfully", data={"url": file_url})

        except Exception as e:
            app.logger.error(f"Error uploading avatar: {e}")
            db.session.rollback()  # Rollback in case of an error
            return create_response(500, message="Error uploading file", data={"error": str(e)})
    else:
        app.logger.error(f"Invalid file type: {file.filename}")
        return create_response(400, message="Invalid file type. Allowed types are png, jpg, jpeg, gif.")


# @app.route("/get-avatar", methods=["GET"])
# @token_required
# def get_avatar(user_id):
#     try:
#         # Fetch the user record
#         user = Users.query.get(user_id)

#         if not user:
#             return (create_response(404, message="User not found"),)

#         if not user.avatar_url:
#             return create_response(404, message="No avatar uploaded for this user")

#         # Return the avatar URL
#         return create_response(200, data={"avatar_url": user.avatar_url})

#     except Exception as e:
#         app.logger.error(f"Error fetching avatar: {e}")
#         return create_response(
#             500,
#             message="An error occurred while fetching avatar",
#             data={"error": str(e)},
#         )
from sqlalchemy.orm import Session
@app.route("/get-avatar", methods=["GET"])
@token_required
def get_avatar(user_id):
    session = Session(bind=db.engine)  # Use session directly
    try:
        user = session.get(Users, user_id)
        if not user:
            return create_response(404, message="User not found")

        if not user.avatar_url:
            return create_response(404, message="No avatar uploaded for this user")

        return create_response(200, data={"avatar_url": user.avatar_url})

    except Exception as e:
        app.logger.error(f"Error fetching avatar: {e}")
        return create_response(
            500,
            message="An error occurred while fetching avatar",
            data={"error": str(e)},
        )


# Helper function to handle fetching data from a table
def fetch_data(model, filters=None):
    query = model.query
    if filters:
        query = query.filter_by(**filters)
    results = query.all()
    return [
        {column.name: getattr(row, column.name) for column in model.__table__.columns}
        for row in results
    ]


@app.route("/users", methods=["GET"])
def get_users():
    user_id = request.args.get("user_id")
    filters = {"id": user_id} if user_id else None
    users = fetch_data(Users, filters)
    return create_response(200, message="users fetched", data=users)


@app.route("/mobile_users", methods=["GET"])
def get_mobile_users():
    phone_number = request.args.get("phone_number")
    filters = {"phone_number": phone_number} if phone_number else None
    mobile_users = fetch_data(MobileUsers, filters)
    return create_response(200, message="users fetched", data=mobile_users)


@app.route("/trackers_info", methods=["GET"])
def get_trackers_info():
    try:
        user_id = request.args.get("user_id")
        trackingId = request.args.get("trackingId")

        filters = {}  # Default filter for non-deleted records

        if user_id:
            filters["user_id"] = user_id
        if trackingId:
            filters["trackingId"] = trackingId

        trackers_info = fetch_data(TrackersInfo, filters)

        if not trackers_info:
            return create_response(200, message="trackers fetched", data=trackers_info)

        return create_response(200, message="trackers fetched", data=trackers_info)

    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return create_response(500, message="An unexpected error occurred")

@app.route('/trackers_info/<int:id>/delivery-proof', methods=['GET'])
@token_required  # Protect route with JWT authentication
def get_delivery_proof(id):
    record = TrackersInfo.query.filter_by(id=id).first()

    if not record:
        return create_response(404, data={"error": "Record not found or you don't have access to this resource"})

    return create_response(200, data={
        "id": record.id,
        "deliveryProofPhotos": record.deliveryProofPhotos
    })

@app.route("/register_device", methods=["POST"])
@token_required
def register_device(current_user_id):
    try:
        data = request.json
        device_token = data.get("deviceToken")
        tracking_id = data.get("trackingId")

        if not device_token or not tracking_id:
            return create_response(
                400,
                message="deviceToken and trackingId are required",
                data={
                    "status": "error",
                    "message": "deviceToken and trackingId are required",
                },
            )

        existing_device = UserDevices.query.filter_by(device_token=device_token).first()
        if existing_device:
            existing_device.trackingId = tracking_id
            db.session.commit()
            return create_response(
                200,
                message="Device token updated",
                data={"status": "success", "message": "Device token updated"},
            )

        new_device = UserDevices(device_token=device_token, trackingId=tracking_id)
        db.session.add(new_device)
        db.session.commit()
        return create_response(
            201,
            message="Device token registered",
            data={"status": "success", "message": "Device token registered"},
        )
    except Exception as e:
        logging.error(f"Error registering device: {e}")
        return create_response(
            500,
            message="Internal server error",
            data={"status": "error", "message": "Internal server error"},
        )


@app.route("/send_notification", methods=["POST"])
@token_required
def send_notification(current_user_id):
    try:
        data = request.json
        tracking_id = data.get("trackingId")
        title = data.get("title")
        message = data.get("message")

        if not tracking_id or not title or not message:
            return create_response(
                400,
                message="trackingId, title, and message are required",
                data={
                    "status": "error",
                    "message": "trackingId, title, and message are required",
                },
            )

        new_notification = Notifications(
            trackingId=tracking_id, title=title, message=message
        )
        db.session.add(new_notification)
        db.session.commit()

        devices = UserDevices.query.filter_by(trackingId=tracking_id).all()
        if devices:
            tokens = [device.device_token for device in devices]
            # For actual notification sending, integrate with your notification service here.
            return create_response(
                200,
                message="Notification added, devices notified",
                data={
                    "status": "success",
                    "message": "Notification added, devices notified",
                },
            )

        return create_response(
            200,
            message="Notification added, but no devices found for this trackingId",
            data={
                "status": "success",
                "message": "Notification added, but no devices found for this trackingId",
            },
        )
    except Exception as e:
        logging.error(f"Error sending notification: {e}")
        return create_response(
            500,
            message="Internal server error",
            data={"status": "error", "message": "Internal server error"},
        )


@app.route("/get_notifications", methods=["GET"])
@token_required
def get_notifications(current_user_id):
    try:
        tracking_id = request.args.get("trackingId")
        if not tracking_id:
            return create_response(
                400,
                message="trackingId is required",
                data={"status": "error", "message": "trackingId is required"},
            )

        notifications = Notifications.query.filter_by(trackingId=tracking_id).all()
        if notifications:
            result = [{"title": n.title, "message": n.message} for n in notifications]
            return create_response(200, message="success", data=result)

        return create_response(
            404,
            message="No notifications found for this trackingId",
            data={
                "status": "error",
                "message": "No notifications found for this trackingId",
            },
        )
    except Exception as e:
        logging.error(f"Error retrieving notifications: {e}")
        return create_response(
            500,
            message="Internal server error",
            data={"status": "error", "message": "Internal server error"},
        )


@app.route("/users_details", methods=["GET"])
@token_required
def get_users_details(user_id=None):  # Add the `user_id` parameter
    try:
        detail_id = request.args.get("id")
        filters = {"id": detail_id} if detail_id else None
        users_details = fetch_data(UsersDetails, filters)
        return create_response(200, message="fetched", data=users_details)
    except Exception as e:
        return create_response(
            500, message="Internal server error", data={"error": str(e)}
        )


@app.route("/user_logins", methods=["GET"])
@token_required
def get_user_logins(user_id):
    user_id = request.args.get("user_id")
    filters = {"user_id": user_id} if user_id else None
    user_logins = fetch_data(UserLogins, filters)
    return create_response(200, message="Fetched", data=user_logins)


@app.route("/contact", methods=["GET"])
def get_contact():
    contact_id = request.args.get("id")
    filters = {"id": contact_id} if contact_id else None
    contacts = fetch_data(Contact, filters)
    return create_response(200, message="Fetched", data=contacts)


@app.route("/subscription", methods=["GET"])
def get_subscription():
    subscription_id = request.args.get("id")
    filters = {"id": subscription_id} if subscription_id else None
    subscriptions = fetch_data(Subscription, filters)
    return create_response(200, message="Fetched", data=subscriptions)


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")
    username = data.get("username")
    user_type = data.get("user_type")
    group_name = data.get("group_name")
    role = data.get("role")
    first_name = data.get("first_name")
    last_name = data.get("last_name")

    # Validate input
    if not (email or phone_number) or (email and not password):
        return create_response(
            400, message="Email or phone number and password are required!"
        )

    # Check if user already exists
    user = None
    if email:
        user = Users.query.filter_by(email=email).first()
    elif phone_number:
        user = Users.query.filter_by(phone_number=phone_number).first()

    if user:
        return create_response(400, message="User already exists")

    if phone_number:
        # Generate OTP and send to phone and email (for phone_number signup)
        otp = generate_otp()
        otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        send_otp(phone_number, otp)  # Function to send OTP via SMS
        if email:
            send_email(
                email, otp
            )  # Function to send OTP via email for phone number users

        # Store the OTP and expiry in the Users table
        new_user = Users(
            phone_number=phone_number,
            otp=otp,
            otp_expiry=otp_expiry,
            username=username,
            role=role,
            group_name=group_name,
            user_type=user_type,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        db.session.add(new_user)
        db.session.commit()

        return create_response(
            200,
            message="OTP sent to phone number (and email if provided). Please verify to complete the signup.",
            data={"otp_verification_required": True},
        )

    # If email is used, proceed with the user creation (no OTP)
    new_user = Users(
        email=email,
        password=password,
        username=username,
        role=role,
        group_name=group_name,
        user_type=user_type,
        first_name=first_name,
        last_name=last_name,
    )
    db.session.add(new_user)
    db.session.commit()

    # Generate JWT token
    token = jwt.encode(
        {
            "sub": new_user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return create_response(
        201,
        message="Signed up successfully.",
        data={
            "token": token,
            "user": {
                "id": new_user.id,
                "email": new_user.email,
                "username": new_user.username,
                "role": new_user.role,
            },
        },
    )


@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    phone_number = data.get("phone_number")
    otp = data.get("otp")

    if not phone_number or not otp:
        return create_response(400, message="Phone number and OTP are required!")

    # Find the user by phone number
    user = Users.query.filter_by(phone_number=phone_number).first()

    if not user:
        return create_response(404, message="User not found")

    if user.otp != otp:
        return create_response(400, message="Invalid OTP")

    if datetime.datetime.utcnow() > user.otp_expiry:
        return create_response(400, message="OTP expired")

    # OTP is valid, finalize user registration
    user.otp = None  # Clear OTP
    user.otp_expiry = None  # Clear OTP expiry
    db.session.commit()

    # Generate JWT token
    token = jwt.encode(
        {
            "sub": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return create_response(
        200,
        message="Signup complete.",
        data={
            "token": token,
            "user": {
                "id": user.id,
                "phone_number": user.phone_number,
                "username": user.username,
                "role": user.role,
            },
        },
    )


@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        phone_number = data.get("phone_number")
        otp = data.get("otp")
        print("data", data, "data")

        # Validate input
        if not (email or phone_number):
            return create_response(400, "Email or phone number is required!")

        if not (password or otp):
            return create_response(400, "Password or OTP is required!")

        user = None

        if email:
            user = Users.query.filter_by(email=email).first()
            if not user:
                return create_response(404, "User not found")
            if not user.check_password(password):
                return create_response(400, "Invalid email or password")

        elif phone_number:
            user = Users.query.filter_by(phone_number=phone_number).first()
            if not user:
                return create_response(404, "User not found")
            if not user.otp:
                return create_response(400, "OTP not set for this user")

            # OTP-based authentication for mobile users or datetime.datetime.utcnow() > user.otp_expiry
            if user.otp != otp:
                return create_response(400, "Invalid or expired OTP")

        # Generate JWT token
        token = jwt.encode(
            {
                "sub": user.id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )

        user_details = {
            "id": user.id,
            "email": user.email if email else None,
            "phone_number": user.phone_number if phone_number else None,
            "username": user.username,
            "role": user.role,
            "is_admin": user.is_admin,
            "avatar": user.avatar,
        }

        return create_response(
            200, {"token": token, "user": user_details}, "Login successful"
        )

    except Exception as e:
        return create_response(500, f"Internal server error: {str(e)}")


# Logout Route
@app.route("/logout", methods=["POST"])
@token_required
def logout(user_id):
    return create_response(
        200, message="Logout successful. Please clear the token on the client-side."
    )


@app.route("/send-otp", methods=["POST"])
def send_otp_request():
    data = request.get_json()
    phone_number = data.get("phone_number")

    if not phone_number:
        return create_response(400, message="Phone number is required!")

    # Validate the phone number format and check if it's a US number
    try:
        parsed_number = phonenumbers.parse(phone_number, "US")
        if not phonenumbers.is_valid_number(parsed_number):
            return create_response(400, message="Invalid phone number!")
        if parsed_number.country_code != 1:  # USA country code is 1
            return create_response(400, message="Only US phone numbers are allowed!")
    except NumberParseException as e:
        return create_response(400, message="Invalid phone number format!")

    otp = generate_otp()
    otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

    mobile_user = Users.query.filter_by(phone_number=phone_number).first()
    if mobile_user:
        mobile_user.otp = otp
        mobile_user.otp_expiry = otp_expiry
    else:
        mobile_user = Users(phone_number=phone_number, otp=otp, otp_expiry=otp_expiry)
        db.session.add(mobile_user)

    db.session.commit()
    send_otp(phone_number, otp)

    return create_response(200, message="OTP sent successfully")


# Create TrackersInfo entries
@app.route("/trackers-info", methods=["POST"])
@token_required
def create_trackers_info(user_id):
    data = request.get_json()

    if not isinstance(data, dict):
        return create_response(400, message=INVALID_FORMAT_MSG)

    entries = data.get("entries", [])

    if not entries:
        return create_response(400, message="No entries provided")

    try:
        new_entries = []
        for entry in entries:
            try:
                loadId = validate_integer(entry.get("loadId"), "loadId")
                trackingId = validate_integer(entry.get("trackingId"), "trackingId")
            except ValueError as e:
                return create_response(400, message=str(e))

            new_entry = TrackersInfo(
                driverPhoneNumber=entry.get("driverPhoneNumber", ""),
                email=entry.get("email", ""),
                comment=entry.get("comment", ""),
                dispatcher=entry.get("dispatcher", ""),
                driver=entry.get("driver", ""),
                brokerName=entry.get("brokerName", ""),
                deliveryProofPhotos=entry.get("deliveryProofPhotos", []),
                isDeleted=entry.get("isDeleted", False),
                locationLogs=entry.get("locationLogs", []),
                shippingData=entry.get("shippingData", {}),
                equipmentType=entry.get("equipmentType", ""),
                latestAvailability=entry.get("latestAvailability", ""),
                loadId=loadId,
                trackingId=trackingId,
                loadStatus=entry.get("loadStatus", ""),
                createdAt=datetime.datetime.utcnow(),
                updatedAt=datetime.datetime.utcnow(),
                user_id=user_id,
            )
            new_entries.append(new_entry)

        db.session.bulk_save_objects(new_entries)
        db.session.commit()

        return create_response(
            201,
            message="TrackersInfo entries created successfully",
            data={"count": len(new_entries)},
        )

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"SQLAlchemyError in create_trackers_info: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG, data={"error": str(e)})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error in create_trackers_info: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )

@app.route("/active-trackers", methods=["POST"])
@token_required
def create_active_tracker(user_id):
    data = request.get_json()

    if not data or "trackingId" not in data:
        return create_response(400, message="Tracking ID is required")

    tracking_id = data["trackingId"]

    try:
        # Find the TrackersInfo entry by the provided trackingId
        tracker_entry = TrackersInfo.query.filter_by(trackingId=tracking_id, user_id=user_id).first()

        if not tracker_entry:
            return create_response(404, message="Tracking ID not found")

        # Check if the tracker is already active
        active_tracker = ActiveTrackers.query.filter_by(trackingId=tracking_id).first()
        if active_tracker:
            return create_response(400, message="Tracker is already active")

        # Create the new ActiveTracker entry
        new_active_tracker = ActiveTrackers(
            trackingId=tracking_id,
            user_id=user_id
        )
        db.session.add(new_active_tracker)

        # Update the loadStatus of the TrackersInfo entry to "LOADING"
        tracker_entry.loadStatus = "LOADING"
        tracker_entry.updatedAt = datetime.datetime.utcnow()

        # Commit the changes to the database
        db.session.commit()

        return create_response(
            201,
            message="Active tracker created successfully and loadStatus updated to LOADING",
            data={
                "id": new_active_tracker.id,
                "trackingId": tracking_id,
                "loadStatus": "LOADING"
            }
        )

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"SQLAlchemyError in create_active_tracker: {e}")
        return create_response(500, message="Database error occurred", data={"error": str(e)})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error in create_active_tracker: {e}")
        return create_response(500, message="An unexpected error occurred", data={"error": str(e)})

# Update TrackersInfo entry by ID
@app.route("/trackers-info/<int:id>", methods=["PUT"])
def update_trackers_info(id):
    # Handle form-data for deliveryProofPhotos
    delivery_photos = request.files.getlist("deliveryProofPhotos")

    # Handle the rest of the data as JSON (optional fields)
    json_data = request.get_json()

    entry = TrackersInfo.query.get(id)


    if not entry:
        return create_response(404, message=NOT_FOUND_MSG)

    # if entry.user_id != user_id:
    #     return create_response(403, message=UNAUTHORIZED_MSG)

    try:
        # Handle deliveryProofPhotos (from form-data)
        if delivery_photos:
            entry.deliveryProofPhotos = entry.deliveryProofPhotos or []  # Initialize if None
            entry.deliveryProofPhotos.extend(photo.filename for photo in delivery_photos)  # Append new photos

            # Save files to the desired directory (example)
            upload_directory = "/path/to/upload/directory"
            for photo in delivery_photos:
                photo.save(os.path.join(upload_directory, photo.filename))

        # Handle the rest of the data (optional JSON fields)
        if json_data:
            for field in [
                "driverPhoneNumber",
                "email",
                "comment",
                "dispatcher",
                "driver",
                "brokerName",
                "isDeleted",
                "locationLogs",
                "shippingData",
                "equipmentType",
                "latestAvailability",
                "loadId",
                "trackingId",
                "loadStatus",
            ]:
                if field in json_data:
                    if field in ["loadId", "trackingId"]:
                        value = validate_integer(json_data[field], field)
                    else:
                        value = json_data[field]
                    setattr(entry, field, value)

            # Handle appending locationLogs (if provided in JSON)
            if "locationLogs" in json_data:
                new_logs = json_data["locationLogs"]
                if isinstance(new_logs, list):
                    entry.locationLogs = entry.locationLogs or []  # Initialize if None
                    entry.locationLogs.extend(new_logs)  # Append new logs

        entry.updatedAt = datetime.datetime.utcnow()
        db.session.commit()

        return create_response(
            200,
            message="TrackersInfo entry updated successfully"
        )

    except ValueError as e:
        return create_response(400, message=str(e))

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"SQLAlchemyError in update_trackers_info: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG, data={"error": str(e)})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error in update_trackers_info: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )

@app.route("/trackers-info/bulk-update", methods=["PUT"])
@token_required
def bulk_update_trackers_info(user_id):
    data = request.get_json()

    if not data or not isinstance(data, dict):
        return create_response(400, message=INVALID_FORMAT_MSG)

    updates = data.get("IDs", [])

    if not updates or not isinstance(updates, list):
        return create_response(400, message="No valid IDs provided")

    ids = [
        update.get("id")
        for update in updates
        if isinstance(update, dict) and "id" in update
    ]

    if not ids:
        return create_response(400, message="No valid IDs found in the request")

    try:
        entries = TrackersInfo.query.filter(TrackersInfo.id.in_(ids)).all()

        if len(entries) != len(ids):
            missing_ids = set(ids) - {entry.id for entry in entries}
            return create_response(
                404, message=f"Some records not found: {missing_ids}"
            )

        entry_dict = {entry.id: entry for entry in entries}

        for update in updates:
            entry_id = update.get("id")
            entry = entry_dict.get(entry_id)

            if not entry:
                app.logger.warning(
                    f"Entry with ID {entry_id} not found in the bulk update"
                )
                continue

            for field in [
                "driverPhoneNumber",
                "email",
                "comment",
                "dispatcher",
                "driver",
                "brokerName",
                "isDeleted",
                "shippingData",
                "equipmentType",
                "latestAvailability",
                "loadId",
                "trackingId",
                "loadStatus",
            ]:
                if field in update:
                    value = update[field]
                    if field in ["loadId", "trackingId"]:
                        value = validate_integer(value, field)
                    setattr(entry, field, value)

            # Append to deliveryProofPhotos if it exists
            if "deliveryProofPhotos" in update:
                if entry.deliveryProofPhotos:
                    entry.deliveryProofPhotos.extend(update["deliveryProofPhotos"])
                else:
                    entry.deliveryProofPhotos = update["deliveryProofPhotos"]

            # Append to locationLogs if it exists
            if "locationLogs" in update:
                if entry.locationLogs:
                    entry.locationLogs.extend(update["locationLogs"])
                else:
                    entry.locationLogs = update["locationLogs"]

            entry.updatedAt = datetime.datetime.utcnow()

        db.session.commit()

        return create_response(
            200,
            message="TrackersInfo entries updated successfully",
            data={"count": len(entries)},
        )

    except ValueError as e:
        return create_response(400, message=str(e))

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"SQLAlchemyError during bulk update of TrackersInfo: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG, data={"error": str(e)})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error during bulk update of TrackersInfo: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )

@app.route("/trackers-info/active", methods=["GET"])
@token_required
def get_active_trackers(user_id):
    try:
        active_trackers = ActiveTracker.query.filter_by(user_id=user_id).all()

        if not active_trackers:
            return create_response(404, message="No active trackers found")

        trackers_list = []
        for tracker in active_trackers:
            trackers_info = TrackersInfo.query.filter_by(trackingId=tracker.trackingId).first()
            if trackers_info and trackers_info.loadStatus != "DELIVERED":
                trackers_list.append({
                    "id": tracker.id,
                    "trackingId": tracker.trackingId,
                    "user_id": tracker.user_id,
                    "loadStatus": trackers_info.loadStatus,
                    "createdAt": tracker.createdAt,
                    "updatedAt": tracker.updatedAt,
                    "trackersInfo": {
                        "driverPhoneNumber": trackers_info.driverPhoneNumber,
                        "email": trackers_info.email,
                        "comment": trackers_info.comment,
                        "dispatcher": trackers_info.dispatcher,
                        "driver": trackers_info.driver,
                        "brokerName": trackers_info.brokerName,
                        "deliveryProofPhotos": trackers_info.deliveryProofPhotos,
                        "locationLogs": trackers_info.locationLogs,
                        "shippingData": trackers_info.shippingData,
                        "equipmentType": trackers_info.equipmentType,
                        "latestAvailability": trackers_info.latestAvailability,
                        "loadId": trackers_info.loadId,
                        "trackingId": trackers_info.trackingId,
                        "loadStatus": trackers_info.loadStatus,
                        "createdAt": trackers_info.createdAt,
                        "updatedAt": trackers_info.updatedAt,
                    }
                })

        return create_response(200, message="Active trackers fetched successfully", data={"active_trackers": trackers_list})

    except SQLAlchemyError as e:
        app.logger.error(f"SQLAlchemyError in get_active_trackers: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG)
    except Exception as e:
        app.logger.error(f"Unexpected error in get_active_trackers: {e}")
        return create_response(500, message="An unexpected error occurred")

@app.route("/trackers-history", methods=["GET"])
@token_required
def get_trackers_history(user_id):
    try:
        delivered_trackers = TrackersInfo.query.filter_by(user_id=user_id, loadStatus="DELIVERED").all()

        if not delivered_trackers:
            return create_response(404, message="No tracker history found")

        history_list = []
        for tracker in delivered_trackers:
            history_list.append({
                "id": tracker.id,
                "trackingId": tracker.trackingId,
                "user_id": tracker.user_id,
                "loadStatus": tracker.loadStatus,
                "createdAt": tracker.createdAt,
                "updatedAt": tracker.updatedAt,
                "trackersInfo": {
                    "driverPhoneNumber": tracker.driverPhoneNumber,
                    "email": tracker.email,
                    "comment": tracker.comment,
                    "dispatcher": tracker.dispatcher,
                    "driver": tracker.driver,
                    "brokerName": tracker.brokerName,
                    "deliveryProofPhotos": tracker.deliveryProofPhotos,
                    "locationLogs": tracker.locationLogs,
                    "shippingData": tracker.shippingData,
                    "equipmentType": tracker.equipmentType,
                    "latestAvailability": tracker.latestAvailability,
                    "loadId": tracker.loadId,
                    "trackingId": tracker.trackingId,
                    "loadStatus": tracker.loadStatus,
                    "createdAt": tracker.createdAt,
                    "updatedAt": tracker.updatedAt,
                }
            })

        return create_response(200, message="Tracker history fetched successfully", data={"trackers_history": history_list})

    except SQLAlchemyError as e:
        app.logger.error(f"SQLAlchemyError in get_trackers_history: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG)
    except Exception as e:
        app.logger.error(f"Unexpected error in get_trackers_history: {e}")
        return create_response(500, message="An unexpected error occurred")

# Delete TrackersInfo entry by ID
@app.route("/trackers-info/<int:id>", methods=["DELETE"])
@token_required
def delete_trackers_info(user_id, id):
    try:
        entry = TrackersInfo.query.get_or_404(id)

        if entry.user_id != user_id:
            return create_response(403, message=UNAUTHORIZED_MSG)

        db.session.delete(entry)
        db.session.commit()

        return create_response(200, message="TrackersInfo entry deleted successfully")

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"SQLAlchemyError in delete_trackers_info: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG, data={"error": str(e)})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error in delete_trackers_info: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )


# Bulk delete TrackersInfo entries
@app.route("/trackers-info/bulk-delete", methods=["DELETE"])
@token_required
def delete_trackers_info_bulk(user_id):
    try:
        data = request.get_json()
        ids = data.get("IDs", [])

        if not ids:
            return create_response(400, message="No IDs provided")

        if not all(isinstance(id, int) for id in ids):
            return create_response(400, message=INVALID_ID_MSG)

        entries = TrackersInfo.query.filter(TrackersInfo.id.in_(ids)).all()

        if len(entries) != len(ids):
            return create_response(
                404, message="Some records not found for the provided IDs"
            )

        for entry in entries:
            if entry.user_id != user_id:
                return create_response(403, message=UNAUTHORIZED_MSG)
            db.session.delete(entry)

        db.session.commit()

        return create_response(200, message="TrackersInfo entries deleted successfully")

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"SQLAlchemyError during bulk delete of TrackersInfo: {e}")
        return create_response(500, message=DATABASE_ERROR_MSG, data={"error": str(e)})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error during bulk delete of TrackersInfo: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )


@app.route("/users-details", methods=["POST"])
@token_required
def create_users_details(user_id):
    try:
        # Get the list of entries from the request payload
        data = request.get_json()
        entries = data.get("entries", [])

        # Check if entries are provided
        if not entries:
            return create_response(400, message="No entries provided")

        # Validate each entry
        new_entries = []
        for entry in entries:
            # Check required fields
            if "data" not in entry or "type" not in entry:
                return create_response(
                    400, message="Missing required fields in one or more entries"
                )

            # Create a UsersDetails object for each entry
            new_entry = UsersDetails(data=entry.get("data"), type=entry.get("type"))
            new_entries.append(new_entry)

        # Bulk save the new entries
        db.session.bulk_save_objects(new_entries)
        db.session.commit()

        return create_response(
            201,
            message="UsersDetails entries created successfully",
            data={"count": len(new_entries)},
        )

    except ValueError as ve:
        # Handle specific ValueError exceptions
        db.session.rollback()
        app.logger.error(f"Value error: {ve}")
        return create_response(
            400, message="Invalid value in request", data={"error": str(ve)}
        )

    except KeyError as ke:
        # Handle specific KeyError exceptions
        db.session.rollback()
        app.logger.error(f"Key error: {ke}")
        return create_response(
            400, message="Missing key in request", data={"error": str(ke)}
        )

    except Exception as e:
        # Handle any other unexpected exceptions
        db.session.rollback()  # Ensure rollback on unexpected errors
        app.logger.error(f"Unexpected error: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )


@app.route("/users-details/<int:id>", methods=["PUT"])
@token_required
def update_users_details(user_id, id):
    data = request.get_json()
    entry = UsersDetails.query.get_or_404(id)

    entry.data = data.get("data", entry.data)
    entry.type = data.get("type", entry.type)

    db.session.commit()

    return create_response(200, message="UsersDetails entry updated successfully")


@app.route("/users-details/bulk-update", methods=["PUT"])
@token_required
def bulk_update_users_details_bulk(user_id):
    data = request.get_json()
    updates = data.get("IDs", [])

    if not updates:
        return create_response(400, message="No update data provided")

    try:
        ids = [update["id"] for update in updates]
        entries = UsersDetails.query.filter(UsersDetails.id.in_(ids)).all()

        if len(entries) != len(ids):
            return create_response(404, message="Some records not found")

        for entry in entries:
            update_data = next((item for item in updates if item["id"] == entry.id), {})
            entry.data = update_data.get("data", entry.data)
            entry.type = update_data.get("type", entry.type)

        db.session.commit()

        return create_response(200, message="UsersDetails entries updated successfully")

    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return create_response(500, message="An unexpected error occurred")


@app.route("/users-details/<int:id>", methods=["DELETE"])
@token_required
def delete_users_details(user_id, id):
    entry = UsersDetails.query.get_or_404(id)
    db.session.delete(entry)
    db.session.commit()

    return create_response(200, message="UsersDetails entry deleted successfully")


@app.route("/users-details/bulk-delete", methods=["DELETE"])
@token_required
def bulk_delete_users_details_bulk(user_id):
    try:
        # Get the list of IDs from the request payload
        data = request.get_json()
        ids = data.get("IDs", [])

        # Check if IDs are provided
        if not ids:
            return create_response(400, message="No IDs provided")

        # Ensure IDs is a list of integers
        if not all(isinstance(id, int) for id in ids):
            return create_response(400, message="Invalid ID format")

        # Query for entries matching the provided IDs
        entries = UsersDetails.query.filter(UsersDetails.id.in_(ids)).all()

        # Check if all requested records were found
        if len(entries) != len(ids):
            return create_response(404, message="Some records not found")

        # Check authorization and delete entries
        for entry in entries:
            # Assuming authorization check is needed; adjust as necessary
            if entry.user_id != user_id:
                return create_response(
                    403, message="Unauthorized to delete some records"
                )
            db.session.delete(entry)

        # Commit the transaction
        db.session.commit()

        return create_response(200, message="UsersDetails entries deleted successfully")

    except ValueError as ve:
        # Handle specific ValueError exceptions
        app.logger.error(f"Value error: {ve}")
        return create_response(
            400, message="Invalid value in request", data={"error": str(e)}
        )

    except KeyError as ke:
        # Handle specific KeyError exceptions
        app.logger.error(f"Key error: {ke}")
        return create_response(
            400, message="Missing key in request", data={"error": str(e)}
        )

    except Exception as e:
        # Handle any other unexpected exceptions
        db.session.rollback()  # Ensure rollback on unexpected errors
        app.logger.error(f"Unexpected error: {e}")
        return create_response(
            500, message="An unexpected error occurred", data={"error": str(e)}
        )


@app.route("/user-logins", methods=["POST"])
@token_required
def create_user_logins(current_user_id):
    print("current_user_id", current_user_id, "current_user_id")
    try:
        # Get JSON data from the request
        data = request.get_json()
        print("data", data, "data")
        
        if not data:
            return create_response(400, message="No data provided")

        # Validate required fields
        if not data.get("device_info") or not data.get("location"):
            return create_response(400, message="Missing required fields: 'device_info' or 'location'")
        
        # Create new entry for UserLogins
        new_entry = UserLogins(
            user_id=current_user_id, 
            device_info=data.get("device_info"),
            location=data.get("location"),
        )
        
        # Add to session and commit the changes
        db.session.add(new_entry)
        db.session.commit()

        return create_response(201, message="UserLogins entry created successfully")

    except IntegrityError as e:
        # Handle database integrity errors (e.g., duplicate entries, foreign key violations)
        db.session.rollback()
        app.logger.error(f"Database integrity error: {e}")
        return create_response(400, message="Database integrity error", data={"error": str(e)})
    
    except Exception as e:
        # General exception handling
        db.session.rollback()
        app.logger.error(f"Unexpected error: {e}")
        return create_response(500, message="An unexpected error occurred", data={"error": str(e)})



@app.route("/user-logins/<int:id>", methods=["PUT"])
@token_required
def update_user_logins(current_user_id, id):
    try:
        # Get JSON data from the request
        data = request.get_json()

        # Check if data is provided
        if not data:
            return create_response(400, message="No data provided")

        # Fetch the entry; raises a 404 error if not found
        entry = UserLogins.query.get_or_404(id)

        # Update fields if provided in the request
        if "device_info" in data:
            entry.device_info = data["device_info"]

        if "location" in data:
            entry.location = data["location"]

        # Commit the changes to the database
        db.session.commit()

        return create_response(200, message="UserLogins entry updated successfully")

    except IntegrityError as e:
        # Handle database integrity errors (e.g., duplicate entries)
        db.session.rollback()
        app.logger.error(f"Database integrity error: {e}")
        return create_response(400, message="Database integrity error", data={"error": str(e)})

    except Exception as e:
        # General exception handling
        db.session.rollback()
        app.logger.error(f"Unexpected error: {e}")
        return create_response(500, message="An unexpected error occurred", data={"error": str(e)})



@app.route("/user-logins/<int:id>", methods=["DELETE"])
@token_required
def delete_user_logins(current_user_id, id):
    try:
        # Fetch the entry; raises a 404 error if not found
        entry = UserLogins.query.get_or_404(id)

        # Optional: Check if the current user has permission to delete this entry
        if entry.user_id != current_user_id and not current_user_id.is_admin:
            return create_response(403, message="Permission denied.")

        # Delete the entry
        db.session.delete(entry)
        db.session.commit()

        return create_response(200, message="UserLogins entry deleted successfully")
    
    except Exception as e:
        # Rollback the session in case of an error
        db.session.rollback()
        app.logger.error(f"Error deleting UserLogins entry with id {id}: {e}")
        return create_response(500, message="An unexpected error occurred", data={"error": str(e)})


# Contact Routes
@app.route("/contact", methods=["POST"])
def contact():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    message = data.get("message")

    if not (username and email and message):
        return create_response(
            400, message="Username, email, and message are required!"
        )

    new_contact = Contact(username=username, email=email, message=message)
    db.session.add(new_contact)
    db.session.commit()

    return create_response(201, message="Contact request submitted successfully")


# Subscription Routes
@app.route("/subscription", methods=["POST"])
def subscribe():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    loads = data.get("loads")
    business = data.get("business")
    phone = data.get("phone")
    company = data.get("company")
    date = data.get("date")

    if not (name and email and loads and business and phone and company and date):
        return create_response(400, message="All fields are required!")

    new_subscription = Subscription(
        name=name,
        email=email,
        loads=loads,
        business=business,
        phone=phone,
        company=company,
        date=datetime.datetime.fromisoformat(date),
    )
    db.session.add(new_subscription)
    db.session.commit()

    return create_response(201, message="Subscription created successfully")


@app.route("/dat_token", methods=["POST"])
def get_dat_token():
    try:
        # Parse JSON data from request
        data = request.get_json()

        if data is None:
            return create_response(400, "No data provided.")

        # Extract values from the request
        username = data.get("username")
        username_organization = data.get("username_organization")
        password_organization = data.get("password_organization")
        access_token = data.get("access_token", "").strip()  # Strip whitespace

        # Validate input
        if not username:
            return create_response(400, "Username is required.")

        if not username_organization or not password_organization:
            return create_response(400, "Organization credentials are required.")

        # Fetch access_token if not provided
        if not access_token:
            access_token = Live_Token.fetch_api_token(
                username_organization, password_organization
            )

        if not access_token:
            return create_response(500, "Failed to fetch the access token.")

        # Set up headers and payload for the DAT API
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        dat_user_api_url = "https://identity.api.dat.com/access/v1/token/user"
        dat_user_payload = {"username": username}

        # Fetch user-specific access token from DAT API
        try:
            dat_user_access_token = Live_Token.fetch_user_access_token(
                dat_user_api_url, headers, dat_user_payload
            )
        except Exception as e:
            app.logger.error(f"Error fetching user access token: {e}")
            return create_response(
                500, "Failed to fetch the user-specific access token."
            )

        if not dat_user_access_token:
            return create_response(
                500, "Failed to fetch the user-specific access token."
            )

        # Save both tokens to a file
        try:
            token_data = {
                "access_token": access_token,
                "dat_user_access_token": dat_user_access_token,
            }
            token_path = Live_Token.save_token_to_file("dat", token_data)
        except Exception as e:
            app.logger.error(f"Error saving token to file: {e}")
            return create_response(500, "Failed to save tokens to file.")

        # Return the saved tokens
        try:
            tokens = Live_Token.get_token_from_file(token_path)
            return jsonify(tokens)
        except Exception as e:
            app.logger.error(f"Error retrieving tokens from file: {e}")
            return create_response(500, "Failed to retrieve tokens from file.")

    except BadRequest as e:
        return create_response(400, f"Invalid request: {str(e)}")
    except Exception as e:
        app.logger.error(f"Error processing dat_token: {e}")
        return create_response(500, f"An error occurred: {str(e)}")


@app.route("/direct_token", methods=["POST"])
def get_direct_token():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    api_token = data.get("api_token")

    if not all([username, password, api_token]):
        return create_response(400, message="Username and password are required.")

    try:
        token = Direct_Token.obtain_access_tokens(username, password, api_token)
        token_path = Live_Token.save_token_to_file("direct", token)
        token_data = Direct_Token.get_token_from_file(token_path)
        if "error" in token_data:
            return create_response(500, data=token_data)
        return jsonify(token_data)
    except Exception as e:
        return create_response(500, message=str(e))


@app.route("/truckstop_token", methods=["POST"])
def get_truckstop_token():
    data = request.json
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    username = data.get("username")
    password = data.get("password")

    if not all([client_id, client_secret, username, password]):
        return create_response(
            400,
            message="client_id, client_secret, username, and password are required.",
        )

    try:
        token = Truckstop_Token.obtain_access_tokens(
            client_id, client_secret, username, password
        )
        token_path = Live_Token.save_token_to_file("truckstop", token)
        token_data = Truckstop_Token.get_token_from_file(token_path)
        return jsonify(token_data)
    except Exception as e:
        return create_response(500, message=str(e))


# API Endpoints for Fetching, Deleting, Updating, and Posting Data to Direct Freight
@app.route("/fetch_postings/<posting_type>", methods=["GET"])
def fetch_postings(posting_type):
    end_user_token = request.headers.get("end-user-token")
    api_token = request.headers.get("api-token")

    if not end_user_token:
        return create_response(400, message="end-user-token header is required.")
    if not api_token:
        return create_response(400, message="api-token header is required.")

    url = f"https://api.directfreight.com/v1/postings/{posting_type}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "end-user-token": end_user_token,
        "api-token": api_token,
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return create_response(
            response.status_code,
            message="Failed to fetch data from Direct Freight API",
            data=response.json(),
        )


@app.route("/fetch_postings/<posting_type>", methods=["DELETE"])
def delete_loads(posting_type):
    end_user_token = request.headers.get("end-user-token")
    api_token = request.headers.get("api-token")
    data = request.json

    if not end_user_token:
        return create_response(400, message="end-user-token header is required.")
    if not api_token:
        return create_response(400, message="api-token header is required.")
    if not data or not isinstance(data.get("posting_ids"), list):
        return create_response(400, message="A list of posting_ids is required.")

    url = f"https://api.directfreight.com/v1/postings/{posting_type}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "end-user-token": end_user_token,
        "api-token": api_token,
    }

    responses = []
    posting_ids = data["posting_ids"]

    # Process posting_ids in batches of 10
    for i in range(0, len(posting_ids), 10):
        batch = posting_ids[i : i + 10]

        for posting_id in batch:
            try:
                response = requests.delete(
                    url, headers=headers, params={"posting_id": posting_id}
                )
                response_data = (
                    response.json()
                    if response.headers.get("Content-Type") == "application/json"
                    else response.text
                )
                responses.append(
                    {
                        "posting_id": posting_id,
                        "status_code": response.status_code,
                        "response": response_data,
                    }
                )
            except requests.RequestException as e:
                # Log error and continue with the next posting_id
                responses.append(
                    {
                        "posting_id": posting_id,
                        "status_code": 500,
                        "response": {"error": str(e)},
                    }
                )

    return jsonify(responses), 200


@app.route("/dat_delete_load_postings", methods=["POST"])
def dat_delete_load_postings():
    # Get the incoming data
    data = request.json

    # Validate the incoming data
    if not data or not isinstance(data.get("ids"), list):
        return jsonify({"error": "A list of ids is required."}), 400

    # Get the authorization token from headers
    auth_token = request.headers.get("Authorization")
    if not auth_token:
        return jsonify({"error": "Authorization token is required."}), 400

    headers = {"Authorization": auth_token, "Content-Type": "application/json"}

    # Initialize a list to hold responses
    responses = []
    ids = data["ids"]

    # Process ids in batches of 10
    for i in range(0, len(ids), 10):
        batch = ids[i : i + 10]

        for id in batch:
            payload = {"type": "DELETE_LOAD_POSTINGS_TASK", "arguments": {"ids": [id]}}

            try:
                response = requests.post(
                    "https://freight.api.dat.com/posting/v2/loads/tasks",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()  # Raise an HTTPError on bad response

                # Log success response
                responses.append(
                    {
                        "id": id,
                        "status": "Deleted successfully",
                        "response": response.json(),
                    }
                )

            except requests.exceptions.HTTPError as http_err:
                # Log the error and continue with the next id
                responses.append(
                    {"id": id, "status": "Failed to delete", "error": str(http_err)}
                )
            except requests.exceptions.RequestException as req_err:
                # Handle any other errors and continue with the next id
                responses.append(
                    {"id": id, "status": "Failed to delete", "error": str(req_err)}
                )

    return jsonify(responses), 200


@app.route("/truckstop_delete_loads", methods=["POST"])
def trucksto_delete_loads():
    # Get the incoming data
    data = request.json

    # Validate the incoming data
    if not data or not isinstance(data.get("loads"), list):
        return jsonify({"error": "A list of loads is required."}), 400

    # Get the authorization token from headers
    auth_token = request.headers.get("Authorization")
    if not auth_token:
        return jsonify({"error": "Authorization token is required."}), 400

    headers = {"Authorization": auth_token, "Content-Type": "application/json"}

    # Initialize a list to hold responses
    responses = []
    loads = data["loads"]

    # Process loads in batches of 10
    for i in range(0, len(loads), 10):
        batch = loads[i : i + 10]

        for load in batch:
            payload = {"loads": [{"loadId": load.get("loadId"), "reason": 2}]}

            try:
                response = requests.post(
                    "https://api.truckstop.com/bulkloadmanagement/v2/deletebulkload",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()  # Raise an HTTPError on bad response

                # Log success response
                responses.append(
                    {
                        "loadId": load.get("loadId"),
                        "status": "Deleted successfully",
                        "response": response.json(),
                    }
                )

            except requests.exceptions.HTTPError as http_err:
                # Log the error and continue with the next load
                responses.append(
                    {
                        "loadId": load.get("loadId"),
                        "status": "Failed to delete",
                        "error": str(http_err),
                    }
                )
            except requests.exceptions.RequestException as req_err:
                # Handle any other errors and continue with the next load
                responses.append(
                    {
                        "loadId": load.get("loadId"),
                        "status": "Failed to delete",
                        "error": str(req_err),
                    }
                )

    return jsonify(responses), 200


@app.route("/fetch_postings/<posting_type>", methods=["PATCH"])
def update_loads(posting_type):
    data = request.json
    end_user_token = request.headers.get("end-user-token")
    api_token = request.headers.get("api-token")

    if not end_user_token:
        return create_response(400, message="end-user-token header is required.")
    if not api_token:
        return create_response(400, message="api-token header is required.")

    url = f"https://api.directfreight.com/v1/postings/{posting_type}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "end-user-token": end_user_token,
        "api-token": api_token,
    }
    response = requests.patch(url, json=data, headers=headers)

    if response.status_code != 200:
        return create_response(
            response.status_code, message="Failed to update data", data=response.json()
        )

    return jsonify(response.json()), response.status_code


@app.route("/fetch_postings/<posting_type>", methods=["POST"])
def post_loads(posting_type):
    data = request.json
    end_user_token = request.headers.get("end-user-token")
    api_token = request.headers.get("api-token")

    if not end_user_token:
        return create_response(400, message="end-user-token header is required.")
    if not api_token:
        return create_response(400, message="api-token header is required.")

    url = f"https://api.directfreight.com/v1/postings/{posting_type}"
    headers = {
        "api-token": api_token,
        "end-user-token": end_user_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 200:
        return create_response(
            response.status_code, message="Failed to post data", data=response.json()
        )

    return jsonify(response.json()), response.status_code


@app.route("/send_sms", methods=["POST"])
@token_required
def send_sms(user_id):
    try:
        data = request.get_json()

        # Validate input data
        to_phone = data.get("to")
        message_body = data.get("message")

        if not to_phone or not message_body:
            return create_response(
                400, message="Phone number and message body are required!"
            )

        # Send the SMS using Twilio
        message = client.messages.create(
            body=message_body, from_=TWILIO_PHONE_NUMBER, to=to_phone
        )

        return create_response(
            200, data={"sid": message.sid}, message="SMS sent successfully!"
        )

    except TwilioRestException as e:
        # Handle Twilio-specific exceptions
        app.logger.error(f"Twilio error: {e}")
        return create_response(400, message=f"Twilio error: {str(e)}")

    except Exception as e:
        # General exception handling
        app.logger.error(f"Unexpected error: {e}")
        return create_response(500, message=f"Failed to send SMS: {str(e)}")



# Utility function to extract and validate the bearer token
def get_bearer_token():
    bearer_token = request.headers.get("Authorization")
    if not bearer_token:
        return None, jsonify({"error": "Authorization header missing"}), 401
    if not bearer_token.startswith("Bearer "):
        return None, jsonify({"error": "Invalid Authorization header format"}), 400
    return bearer_token, None


@app.route("/trucker_update_load", methods=["POST"])
def truckerpath_update_load():
    bearer_token, error_response = get_bearer_token()
    if error_response:
        return error_response

    headers = {"Authorization": bearer_token, "Content-Type": "application/json"}

    data = request.json
    response = requests.post(
        "https://api.truckerpath.com/truckload/api/shipments/update/v2",
        json=data,
        headers=headers,
    )
    if response.status_code == 200:
        return jsonify({"message": "Updated successfully!"}), 200
    else:
        return jsonify({"error": response.text}), response.status_code


@app.route("/trucker_delete_load", methods=["POST"])
def truckerpath_delete_load():
    bearer_token, error_response = get_bearer_token()
    if error_response:
        return error_response

    headers = {"Authorization": bearer_token, "Content-Type": "application/json"}

    data = request.json
    external_ids = data.get("external_id", [])
    results = []

    # Process external_ids in batches of 10
    for i in range(0, len(external_ids), 10):
        batch = external_ids[i : i + 10]

        for external_id in batch:
            response = requests.post(
                "https://api.truckerpath.com/truckload/api/shipments/delete/v2",
                json={"external_id": [external_id]},
                headers=headers,
            )
            if response.status_code == 200:
                results.append(
                    {"external_id": external_id, "status": "Deleted successfully"}
                )
            else:
                results.append(
                    {
                        "external_id": external_id,
                        "status": "Failed to delete",
                        "error": response.text,
                    }
                )

    return jsonify(results), 200


@app.route("/trucker_submit_load", methods=["POST"])
def truckerpath_submit_load():
    bearer_token, error_response = get_bearer_token()
    if error_response:
        return error_response

    headers = {"Authorization": bearer_token, "Content-Type": "application/json"}

    data = request.json
    response = requests.post(
        "https://api.truckerpath.com/truckload/api/shipments/v2",
        json=data,
        headers=headers,
    )
    if response.status_code == 200:
        return jsonify({"message": "Submitted successfully!"}), 200
    else:
        return jsonify({"error": response.text}), response.status_code


@app.route("/trucker_fetch_loads", methods=["POST"])
def truckerpath_fetch_loads():
    bearer_token, error_response = get_bearer_token()
    data = request.json
    if error_response:
        return error_response

    headers = {"Authorization": bearer_token, "Content-Type": "application/json"}

    page_num = data.get("page_num")
    page_size = data.get("page_size")

    payload = {"page_num": page_num, "page_size": page_size}

    response = requests.post(
        "https://api.truckerpath.com/truckload/api/shipments/query/page/total",
        json=payload,
        headers=headers,
    )

    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({"error": response.text}), response.status_code


@app.route("/trucker_fetch_company", methods=["GET"])
def truckerpath_fetch_company():
    bearer_token, error_response = get_bearer_token()
    if error_response:
        return error_response

    headers = {"Authorization": bearer_token, "Content-Type": "application/json"}

    response = requests.get(
        "https://api.truckerpath.com/truckload/api/company/query/list", headers=headers
    )

    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({"error": response.text}), response.status_code


@app.route("/get_tokens", methods=["POST"])
def get_tokens():
    try:
        # Extract username and password from the request body
        auth_data = request.json
        username = auth_data.get("username")
        password = auth_data.get("password")
        access_token = auth_data.get("access_token")

        # Validate credentials
        if username != "thomas@jakebrakelogistics.com" or password != "Blackfish69y2k":
            return jsonify({"error": "Unauthorized: Invalid credentials."}), 401

        # Initialize the result dictionary with default values
        result = {
            "dat_user_access_token": None,
            "direct_token": None,
            "truckstop_token": None,
            "truckerpath_token": TRUCKERPATH_TOKEN,  # Always include TruckerPath token
            "direct_api_key": DIRECT_CREDENTIALS["api_token"],
            "error_messages": [],
        }

        DAT_CREDENTIALS1 = {
            "username": "thomas@jakebrakelogistics.com",
            "username_organization": "adrian@jakebrakelogistics.com",
            "password_organization": "Sharmaboy@3456789",
            "access_token": access_token,
        }

        # Function to make API requests
        def fetch_token(url, payload, token_type):
            try:
                response = requests.post(url, json=payload, timeout=10)
                response.raise_for_status()  # Raise an exception for 4xx/5xx errors
                return response.json()
            except requests.Timeout:
                result["error_messages"].append(f"Timeout fetching {token_type}.")
                return None
            except requests.RequestException as e:
                result["error_messages"].append(
                    f"Failed to fetch {token_type}: {str(e)}"
                )
                return None

        # Fetch DAT Token and DAT User Access Token
        dat_response = fetch_token(
            "https://load41-flask.vercel.app/dat_token",
            DAT_CREDENTIALS1,
            "DAT token and DAT User Access token",
        )
        if dat_response:
            result["dat_user_access_token"] = dat_response.get("access_token")

        # Fetch Direct Token
        direct_response = fetch_token(
            "https://load41-flask.vercel.app/direct_token",
            DIRECT_CREDENTIALS,
            "Direct token",
        )
        if direct_response:
            result["direct_token"] = direct_response.get("access_token")

        # Fetch Truckstop Token
        truckstop_response = fetch_token(
            "https://load41-flask.vercel.app/truckstop_token",
            TRUCKSTOP_CREDENTIALS,
            "Truckstop token",
        )
        if truckstop_response:
            result["truckstop_token"] = truckstop_response.get("access_token")

        # Return the result with all tokens and error messages
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


# Endpoint to fetch the current state of the table
@app.route("/trackers_info/real_time", methods=["GET"])
def get_trackers_info_realtime():
    tracking_id = request.args.get("tracking_id")

    if not tracking_id:
        return jsonify({"status": "error", "message": "tracking_id is required"}), 400

    trackers_info = TrackersInfo.query.filter_by(trackingId=tracking_id).all()

    if not trackers_info:
        return (
            jsonify(
                {"status": "error", "message": "No data found for this tracking ID"}
            ),
            404,
        )

    result = [
        {
            "id": info.id,
            "driverPhoneNumber": info.driverPhoneNumber,
            "email": info.email,
            "comment": info.comment,
            "datetimes": info.datetimes,
            "dispatcher": info.dispatcher,
            "driver": info.driver,
            "brokerName": info.brokerName,
            "locationLogs": info.locationLogs,
            "shippingData": info.shippingData,
            "equipmentType": info.equipmentType,
            "latestAvailability": info.latestAvailability,
            "price": str(info.price),
            "loadStatus": info.loadStatus,
            "createdAt": info.createdAt,
            "updatedAt": info.updatedAt,
        }
        for info in trackers_info
    ]

    return jsonify(result), 200


# Notify clients of changes
def notify_clients(tracker_info, action):
    data = {
        "action": action,
        "id": tracker_info.id,
        "driverPhoneNumber": tracker_info.driverPhoneNumber,
        "email": tracker_info.email,
        "comment": tracker_info.comment,
        "datetimes": tracker_info.datetimes,
        "dispatcher": tracker_info.dispatcher,
        "driver": tracker_info.driver,
        "brokerName": tracker_info.brokerName,
        "locationLogs": tracker_info.locationLogs,
        "shippingData": tracker_info.shippingData,
        "equipmentType": tracker_info.equipmentType,
        "latestAvailability": tracker_info.latestAvailability,
        "price": str(tracker_info.price),
        "loadStatus": tracker_info.loadStatus,
        "createdAt": tracker_info.createdAt,
        "updatedAt": tracker_info.updatedAt,
    }
    socketio.emit("tracker_update", data)


# Listen for insert, update, and delete events in TrackersInfo table
@event.listens_for(TrackersInfo, "after_insert")
def after_insert(mapper, connection, target):
    notify_clients(target, action="insert")


@event.listens_for(TrackersInfo, "after_update")
def after_update(mapper, connection, target):
    notify_clients(target, action="update")


@event.listens_for(TrackersInfo, "after_delete")
def after_delete(mapper, connection, target):
    notify_clients(target, action="delete")


# Handle real-time connections
@socketio.on("connect")
def handle_connect():
    print("Client connected")
    emit("message", {"data": "Connected to real-time tracker updates"})


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # socketio.run(app, host="0.0.0.0", port=6969, debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True) 
    # app.run(host="0.0.0.0", port=6969, debug=True)
    # socketio.run(app, debug=True)
