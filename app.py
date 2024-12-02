from flask import Flask, jsonify, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
import json
from flask_session import Session
import pytz

from flask_bcrypt import Bcrypt
from functools import wraps
from urllib.parse import urlparse
from sqlalchemy.orm import joinedload
from itsdangerous import URLSafeTimedSerializer
from flask_cors import CORS
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from sqlalchemy import extract,func, cast, Date, or_
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import calendar

import os

SECRET_KEY = "your_secret_key"  # Use a secure value here (e.g., from an environment variable)

app = Flask(__name__)
bcrypt = Bcrypt(app)
serializer = URLSafeTimedSerializer(SECRET_KEY)
CORS(app, supports_credentials=True, origins=["http://localhost:5173", "http://127.0.0.1:5173", "https://jwhitproductionstattooparlor.netlify.app"], allow_headers=["Content-Type", "Authorization"])

if os.getenv('FLASK_ENV') == 'production':
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')  # Use the deployed database
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'  # Use a local SQLite databaseapp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)



@app.before_request
def before_request():
    """
    Global token verification applied before each request.
    Skips validation for OPTIONS requests and public endpoints.
    """
    # Allow OPTIONS requests to bypass token verification
    if request.method == 'OPTIONS':
        return '', 204

    # List of public endpoints that don't require authentication
    public_endpoints = ['signup', 'signin', 'reset_password', 'get_piercings','send_message', 'get_booking', 'request_password_reset',  'delete_photo','search_piercings_by_name', 'search_bookings_by_name','search_piercings_and_bookings','get_average_rating', 'artists' ,'get_artist_by_id','get_artist_bookings','create_review','get_reviews','get_gallery', 'bookings', 'create_booking', 'get_all_galleries', 'show_create_artist_button','create_inquiry', 'create_piercing', 'delete_booking', 'delete_piercing', 'update_piercing', 'update_booking', 'get_or_create_global_setting','subscribe', 'get_newsletters', 'delete_newsletter','create_newsletter', 'get_subscribers', 'unsubscribe']
    if request.endpoint in public_endpoints:
        return  # Skip token validation for public endpoints

    # Extract the token from the Authorization header
    token = request.headers.get('Authorization', '').split(" ")[1] if 'Authorization' in request.headers else None

    if not token:
        return jsonify({'error': 'Token is missing'}), 401

    try:
        # Verify the token and decode the payload
        payload = verify_token(token)
        if not payload:
            raise jwt.InvalidTokenError

        # Attach user information to the request object
        request.user_id = payload.get('user_id')
        request.username = payload.get('username')
        request.user_type = payload.get('user_type')

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

def format_datetime(dt):
    """Format a datetime object into the desired string format."""
    return dt.strftime("%A, %B %d, %Y %I:%M %p") if dt else None
def is_valid_url(url):
    regex = re.compile(
        r"^(https?://)?"
        r"([a-z0-9-]+\.)+[a-z]{2,6}"
        r"(:[0-9]{1,5})?"
        r"(/.*)?$",
        re.IGNORECASE,
    )
    return re.match(regex, url) is not None

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Ensure the user data is available from the request object
        if not hasattr(request, 'user_id'):
            return jsonify({'error': 'Unauthorized access'}), 403
        return f(*args, **kwargs)
    return decorated

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user_id'):
            return jsonify({'error': 'Unauthorized access'}), 403

        current_user = User.query.get(request.user_id)
        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        return f(current_user, *args, **kwargs)
    return decorated



@app.get('/api/artists/<int:artist_id>/bookings', endpoint='get_artist_bookings')
def get_artist_bookings(artist_id):
    """
    Public endpoint to get all bookings for a specific artist.
    """
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({"error": "Artist not found"}), 404

    bookings = Booking.query.filter_by(artist_id=artist_id).all()
    return jsonify([booking.to_dict() for booking in bookings]), 200

@app.delete('/api/users/<int:user_id>')
@token_required
def delete_user(current_user, user_id):
    if current_user.user_type != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.delete('/api/artists/<int:artist_id>')
@token_required
def delete_artist(current_user, artist_id):
    """
    Delete an artist. Only the creator or an admin can delete.
    """
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Check permissions
    if current_user.user_type != 'admin' and current_user.id != artist.created_by:
        return jsonify({'error': 'Unauthorized access'}), 403

    try:
        db.session.delete(artist)
        db.session.commit()
        return jsonify({'message': 'Artist deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500



#--------------------------------------------------------------------------------------------#
# Booking Model
class Booking(db.Model, SerializerMixin):
    __tablename__ = "bookings"

    id = db.Column(db.Integer, primary_key=True)
    booking_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    tattoo_style = db.Column(db.String(50), nullable=False)
    tattoo_size = db.Column(db.String(50), nullable=False)
    placement = db.Column(db.String(50), nullable=False)
    artist_id = db.Column(db.Integer, db.ForeignKey("artists.id", name="fk_booking_artist"), nullable=False)
    studio_location = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default="unpaid")
    status = db.Column(db.String(20), default="pending")
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    call_or_text_preference = db.Column(db.String(10), nullable=False)  # Choices: 'call', 'text'
    artist = db.relationship("Artist", back_populates="bookings")

    serialize_rules = ("-artist.bookings",)

    def to_dict(self):

        booking_dict = super().to_dict()
        booking_dict["booking_date"] = format_datetime(self.booking_date)
        booking_dict["appointment_date"] = format_datetime(self.appointment_date)
        return booking_dict

@app.post('/api/bookings', endpoint='create_booking')
def create_booking():
    data = request.get_json()
    tattoo_style = data.get('tattoo_style')
    tattoo_size = data.get('tattoo_size')
    placement = data.get('placement')
    artist_id = data.get('artist_id')
    studio_location = data.get('studio_location')
    appointment_date = data.get('appointment_date')
    price = data.get('price')
    name = data.get('name')
    phone_number = data.get('phone_number')
    call_or_text_preference = data.get('call_or_text_preference')

    if not all([tattoo_style, tattoo_size, placement, artist_id, studio_location, appointment_date, price, name, phone_number, call_or_text_preference]):
        return jsonify({'error': 'All fields are required'}), 400

    try:
        appointment_date_obj = datetime.strptime(appointment_date, '%A, %B %d, %Y %I:%M %p')
        if appointment_date_obj <= datetime.now():
            return jsonify({'error': 'Appointment date must be in the future'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use "Thursday, April 1, 2024 5:00 PM".'}), 400

    new_booking = Booking(
        tattoo_style=tattoo_style,
        tattoo_size=tattoo_size,
        placement=placement,
        artist_id=artist_id,
        studio_location=studio_location,
        appointment_date=appointment_date_obj,
        price=price,
        name=name,
        phone_number=phone_number,
        call_or_text_preference=call_or_text_preference
    )

    db.session.add(new_booking)
    db.session.commit()
    return jsonify(new_booking.to_dict()), 201

@app.patch('/api/bookings/<int:booking_id>')
def update_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404

    data = request.get_json()
    
    if 'tattoo_style' in data:
        booking.tattoo_style = data['tattoo_style']
    if 'tattoo_size' in data:
        booking.tattoo_size = data['tattoo_size']
    if 'placement' in data:
        booking.placement = data['placement']
    if 'artist_id' in data:
        booking.artist_id = data['artist_id']
    if 'studio_location' in data:
        booking.studio_location = data['studio_location']
    if 'appointment_date' in data:
        try:
            appointment_date_obj = datetime.strptime(data['appointment_date'], '%A, %B %d, %Y %I:%M %p')
            if appointment_date_obj <= datetime.now():
                return jsonify({'error': 'Appointment date must be in the future'}), 400
            booking.appointment_date = appointment_date_obj
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use "Thursday, April 1, 2024 5:00 PM".'}), 400
    if 'price' in data:
        booking.price = data['price']
    if 'payment_status' in data:
        booking.payment_status = data['payment_status']
    if 'status' in data:
        booking.status = data['status']

    db.session.commit()
    return jsonify(booking.to_dict()), 200

@app.get('/api/bookings', endpoint='bookings')
def get_bookings():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    bookings = Booking.query.paginate(page=page, per_page=per_page)

    return jsonify({
        "bookings": [booking.to_dict() for booking in bookings.items],
        "total_items": bookings.total,
        "total_pages": bookings.pages,
        "current_page": bookings.page
    }), 200


@app.get('/api/bookings/<int:booking_id>')
def get_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404
    return jsonify(booking.to_dict()), 200

@app.delete('/api/bookings/<int:booking_id>')
def delete_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404

    db.session.delete(booking)
    db.session.commit()
    return jsonify({'message': 'Booking deleted successfully'}), 200

@app.get('/api/bookings/search', endpoint='search_bookings_by_name')
def search_bookings_by_name():
    """
    Search for bookings by the client's name.
    """
    name = request.args.get('name', "").strip()

    if not name:
        return jsonify({'error': 'Search query is required'}), 400

    bookings = Booking.query.filter(Booking.name.ilike(f"%{name}%")).all()

    if not bookings:
        return jsonify({'message': 'No bookings found matching the search query.'}), 404

    return jsonify([booking.to_dict() for booking in bookings]), 200

#-----------------------------------------------------------------------------------------------#
class Piercing(db.Model, SerializerMixin):
    __tablename__ = "piercings"

    id = db.Column(db.Integer, primary_key=True)
    booking_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    piercing_type = db.Column(db.String(50), nullable=False)  # e.g., ear, nose, belly button
    jewelry_type = db.Column(db.String(50), nullable=False)   # e.g., stud, hoop
    placement = db.Column(db.String(50), nullable=False)      # Specific location, e.g., "left ear lobe"
    artist_id = db.Column(db.Integer, db.ForeignKey("artists.id", name="fk_piercing_artist"), nullable=True)
    studio_location = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default="unpaid")
    status = db.Column(db.String(20), default="pending")
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    call_or_text_preference = db.Column(db.String(10), nullable=False)  # Choices: 'call', 'text'
    artist = db.relationship("Artist", lazy="joined")

    serialize_rules = ("-artist.piercings",)

    def to_dict(self):

        
        piercing_dict = super().to_dict()
        piercing_dict["booking_date"] = format_datetime(self.booking_date)
        piercing_dict["appointment_date"] = format_datetime(self.appointment_date)
        return piercing_dict

@app.post('/api/piercings', endpoint='create_piercing')
def create_piercing():
    data = request.get_json()
    piercing_type = data.get('piercing_type')
    jewelry_type = data.get('jewelry_type')
    placement = data.get('placement')
    studio_location = data.get('studio_location')
    appointment_date = data.get('appointment_date')
    price = data.get('price')
    name = data.get('name')
    phone_number = data.get('phone_number')
    call_or_text_preference = data.get('call_or_text_preference')
    artist_id = data.get('artist_id')  # Add artist_id

    if not all([piercing_type, jewelry_type, placement, studio_location, appointment_date, price, name, phone_number, call_or_text_preference]):
        return jsonify({'error': 'All fields are required'}), 400

    try:
        appointment_date_obj = datetime.strptime(appointment_date, '%A, %B %d, %Y %I:%M %p')
        if appointment_date_obj <= datetime.now():
            return jsonify({'error': 'Appointment date must be in the future'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use "Thursday, April 1, 2024 5:00 PM".'}), 400

    new_piercing = Piercing(
        piercing_type=piercing_type,
        jewelry_type=jewelry_type,
        placement=placement,
        studio_location=studio_location,
        appointment_date=appointment_date_obj,
        price=price,
        name=name,
        phone_number=phone_number,
        call_or_text_preference=call_or_text_preference,
                artist_id=artist_id  # Include artist_id

    )

    db.session.add(new_piercing)
    db.session.commit()
    return jsonify(new_piercing.to_dict()), 201


@app.get('/api/piercings', endpoint='get_piercings')
def get_piercings():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    piercings = Piercing.query.paginate(page=page, per_page=per_page)

    return jsonify({
        "piercings": [piercing.to_dict() for piercing in piercings.items],
        "total_items": piercings.total,
        "total_pages": piercings.pages,
        "current_page": piercings.page
    }), 200

@app.get('/api/piercings/<int:piercing_id>',  endpoint='get_piercing')
def get_piercing(piercing_id):


    piercing = Piercing.query.get(piercing_id)
    if not piercing:
        return jsonify({'error': 'Piercing not found'}), 404
    return jsonify(piercing.to_dict()), 200


@app.patch('/api/piercings/<int:piercing_id>')
def update_piercing(piercing_id):



    piercing = Piercing.query.get(piercing_id)
    if not piercing:
        return jsonify({'error': 'Piercing not found'}), 404

    data = request.get_json()
    if 'piercing_type' in data:
        piercing.piercing_type = data['piercing_type']
    if 'jewelry_type' in data:
        piercing.jewelry_type = data['jewelry_type']
    if 'placement' in data:
        piercing.placement = data['placement']
    if 'studio_location' in data:
        piercing.studio_location = data['studio_location']
    if 'appointment_date' in data:
        try:
            appointment_date_obj = datetime.strptime(data['appointment_date'], '%A, %B %d, %Y %I:%M %p')
            if appointment_date_obj <= datetime.now():
                return jsonify({'error': 'Appointment date must be in the future'}), 400
            piercing.appointment_date = appointment_date_obj
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use "Thursday, April 1, 2024 5:00 PM".'}), 400
    if 'price' in data:
        piercing.price = data['price']
    if 'payment_status' in data:
        piercing.payment_status = data['payment_status']
    if 'status' in data:
        piercing.status = data['status']
    if 'artist_id' in data:  # Validate and update the artist_id if provided
        artist_id = data['artist_id']
        artist = Artist.query.get(artist_id)
        if not artist:
            return jsonify({'error': 'Artist not found'}), 404
        piercing.artist_id = artist_id
    if 'name' in data:
        piercing.name = data['name']
    if 'phone_number' in data:
        piercing.phone_number = data['phone_number']
    if 'call_or_text_preference' in data:
        if data['call_or_text_preference'] not in ['call', 'text']:
            return jsonify({'error': 'Invalid preference. Choose "call" or "text".'}), 400
        piercing.call_or_text_preference = data['call_or_text_preference']

    db.session.commit()
    return jsonify(piercing.to_dict()), 200

@app.delete('/api/piercings/<int:piercing_id>')
def delete_piercing(piercing_id):

    piercing = Piercing.query.get(piercing_id)
    if not piercing:
        return jsonify({'error': 'Piercing not found'}), 404

    db.session.delete(piercing)
    db.session.commit()
    return jsonify({'message': 'Piercing deleted successfully'}), 200


@app.get('/api/piercings/search', endpoint='search_piercings_by_name')
def search_piercings_by_name():
    """
    Search for piercings by the client's name.
    """
    name = request.args.get('name', "").strip()

    if not name:
        return jsonify({'error': 'Search query is required'}), 400

    piercings = Piercing.query.filter(Piercing.name.ilike(f"%{name}%")).all()

    if not piercings:
        return jsonify({'message': 'No piercings found matching the search query.'}), 404

    return jsonify([piercing.to_dict() for piercing in piercings]), 200

#--------------------------------------------------------------------------------------------#
# Artist Model
class Artist(db.Model, SerializerMixin):
    __tablename__ = "artists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    specialties = db.Column(db.String(200), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    social_media = db.Column(db.Text, nullable=True)  # Updated to store a string
    years_of_experience = db.Column(db.Integer, nullable=True)
    styles = db.Column(db.JSON, nullable=True, default=[])  # Default to empty list
    average_rating = db.Column(db.Float, nullable=True, default=0.0)
    location = db.Column(db.String(100), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    availability_schedule = db.Column(db.JSON, nullable=True, default={})  # Default to empty dict
    certifications = db.Column(db.Text, nullable=True)
    awards = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now(), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key to User model

    reviews = db.relationship("Review", back_populates="artist", cascade="all, delete-orphan")
    gallery = db.relationship("Gallery", back_populates="artist", cascade="all, delete-orphan")
    bookings = db.relationship("Booking", back_populates="artist", cascade="all, delete-orphan")

    serialize_rules = ("-bookings.artist", "-reviews.artist")

    def to_dict(self):
        artist_dict = super().to_dict()
        artist_dict["social_media"] = self.parse_social_media()
        artist_dict["styles"] = self.styles or []  # Directly use the JSON field
        artist_dict["created_at"] = format_datetime(self.created_at)
        artist_dict["updated_at"] = format_datetime(self.updated_at)
        artist_dict["is_active"] = self.is_active
        return artist_dict


    def parse_social_media(self):
        """
        Converts the stored social_media string into a structured dictionary.
        Example: "Twitter: @handle, Instagram: @insta" -> {"Twitter": "@handle", "Instagram": "@insta"}
        """
        if not self.social_media:
            return {}
        return dict(item.strip().split(": ") for item in self.social_media.split(",") if ": " in item)

# Utility Function
def validate_json(data, required_fields):
    """
    Validate that all required fields are present in the data.
    """
    return all(field in data for field in required_fields)

@app.route('/api/artists', methods=['POST'])
@token_required
def create_artist(current_user):
    """
    Create a new artist. Requires authentication.
    """
    # Allow both Admin and Artist users to create an artist
    if current_user.user_type not in ['admin', 'artist']:
        return jsonify({"error": "Unauthorized access"}), 403

    # Parse and validate request data
    data = request.get_json()
    required_fields = ["name"]
    if not validate_json(data, required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    try:
        # Serialize fields to JSON
        social_media = json.dumps(data.get('social_media', {}))  # Convert dict to JSON string
        styles = json.dumps(data.get('styles', []))  # Convert list to JSON string
        availability_schedule = json.dumps(data.get('availability_schedule', {}))  # Convert dict to JSON string

        # Create an Artist instance
        new_artist = Artist(
            name=data['name'],
            specialties=data.get('specialties'),
            bio=data.get('bio'),
            social_media=social_media,  # Store as JSON string
            years_of_experience=data.get('years_of_experience'),
            styles=styles,  # Store as JSON string
            average_rating=data.get('average_rating', 0.0),
            location=data.get('location'),
            profile_picture=data.get('profile_picture'),
            availability_schedule=availability_schedule,  # Store as JSON string
            certifications=data.get('certifications'),
            awards=data.get('awards'),
            is_active=data.get('is_active', True),
            created_by=current_user.id  # Automatically associate with the current user
        )

        # Add to the database
        db.session.add(new_artist)
        db.session.commit()

        return jsonify({"message": "Artist created successfully", "artist": new_artist.to_dict()}), 201

    except IntegrityError as e:
        db.session.rollback()
        return jsonify({"error": f"Integrity error: {str(e.orig)}"}), 400
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500




@app.get('/api/artists/<int:artist_id>')
def get_artist_by_id(artist_id):
    """Public endpoint to fetch an artist profile."""
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({"error": "Artist not found"}), 404
    return jsonify(artist.to_dict()), 200

@app.patch('/api/artists/<int:artist_id>')
@token_required
def update_artist(current_user, artist_id):
    """
    Update an artist's details. Allows only the artist creator or admin to update.
    """
    # Fetch the artist
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Check permissions
    if current_user.user_type != 'admin' and current_user.id != artist.created_by:
        return jsonify({'error': 'Unauthorized access'}), 403

    # Parse request data
    data = request.get_json()

    # Update fields if provided
    if "name" in data:
        artist.name = data["name"]
    if "specialties" in data:
        artist.specialties = data["specialties"]
    if "bio" in data:
        artist.bio = data["bio"]
    if "social_media" in data:
        if isinstance(data["social_media"], dict):
            # Serialize the social media dictionary into a string
            artist.social_media = ", ".join([f"{k}: {v}" for k, v in data["social_media"].items()])
        elif isinstance(data["social_media"], str):
            artist.social_media = data["social_media"]
        else:
            return jsonify({"error": "Invalid social_media format. Must be a dictionary or string."}), 400
    if "styles" in data:
        if isinstance(data["styles"], list):
            artist.styles = data["styles"]
        else:
            return jsonify({"error": "Invalid styles format. Must be a list."}), 400
    if "years_of_experience" in data:
        if isinstance(data["years_of_experience"], int):
            artist.years_of_experience = data["years_of_experience"]
        else:
            return jsonify({"error": "Invalid years_of_experience format. Must be an integer."}), 400
    if "location" in data:
        artist.location = data["location"]
    if "profile_picture" in data:
        artist.profile_picture = data["profile_picture"]
    if "availability_schedule" in data:
        if isinstance(data["availability_schedule"], dict):
            artist.availability_schedule = data["availability_schedule"]
        else:
            return jsonify({"error": "Invalid availability_schedule format. Must be a dictionary."}), 400
    if "certifications" in data:
        artist.certifications = data["certifications"]
    if "awards" in data:
        artist.awards = data["awards"]
    if "is_active" in data:
        if isinstance(data["is_active"], bool):
            artist.is_active = data["is_active"]
        else:
            return jsonify({"error": "Invalid is_active format. Must be a boolean."}), 400

    # Commit updates to the database
    try:
        db.session.commit()
        return jsonify(artist.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.get('/api/artists', endpoint='artists')
def get_all_artists():
    """
    Fetch all artists.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)

    artists_query = Artist.query.paginate(page=page, per_page=per_page)

    return jsonify({
        "artists": [artist.to_dict() for artist in artists_query.items],
        "total_items": artists_query.total,
        "total_pages": artists_query.pages,
        "current_page": artists_query.page
    }), 200


@app.get('/api/artists/search')
def search_artists():
    """
    Search for artists by style, name, or minimum years of experience.
    """
    style = request.args.get("style")
    name = request.args.get("name")
    min_experience = request.args.get("min_experience", type=int)

    query = Artist.query

    # Search for a style in the JSON array
    if style:
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith("sqlite"):
            # SQLite JSON extraction
            query = query.filter(func.json_extract(Artist.styles, '$[*]').like(f'%{style}%'))
        else:
            # PostgreSQL JSONB contains
            query = query.filter(Artist.styles.contains([style]))

    # Search by name
    if name:
        query = query.filter(Artist.name.ilike(f"%{name}%"))

    # Filter by minimum years of experience
    if min_experience is not None:
        query = query.filter(Artist.years_of_experience >= min_experience)

    # Execute the query
    artists = query.all()

    # Return the results
    if not artists:
        return jsonify({"message": "No artists found."}), 404

    return jsonify([artist.to_dict() for artist in artists]), 200



@app.patch('/api/artists/<int:artist_id>/deactivate')
@token_required
def deactivate_artist(current_user, artist_id):
    """
    Deactivate or activate an artist. Admin-only action.
    """
    # Ensure the user is an admin
    if current_user.user_type != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403

    # Fetch the artist
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    # Parse the request data
    data = request.get_json()
    is_active = data.get('is_active')

    # Validate the input
    if not isinstance(is_active, bool):
        return jsonify({'error': 'Invalid value for is_active. Must be a boolean.'}), 400

    # Update the artist's status
    artist.is_active = is_active
    db.session.commit()

    # Prepare the response
    status = "activated" if is_active else "deactivated"
    return jsonify({'message': f'Artist {status} successfully', 'artist': artist.to_dict()}), 200

#--------------------------------------------------------------------#

class Review(db.Model, SerializerMixin):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    artist_id = db.Column(db.Integer, db.ForeignKey("artists.id"), nullable=False)
    star_rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    review_text = db.Column(db.Text, nullable=True)  # Optional written review
    photo_url = db.Column(db.String(255), nullable=True)  # URL of uploaded photo
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    artist = db.relationship("Artist", back_populates="reviews")
    serialize_rules = ("-artist.reviews",)
@app.post('/api/artists/<int:artist_id>/reviews')
def create_review(artist_id):
    data = request.get_json()
    star_rating = data.get("star_rating")
    review_text = data.get("review_text")
    photo_url = data.get("photo_url")

    # Validate star_rating
    try:
        star_rating = int(star_rating)  # Convert to integer
    except (ValueError, TypeError):
        return jsonify({"error": "Star rating must be an integer between 1 and 5"}), 400

    if not (1 <= star_rating <= 5):
        return jsonify({"error": "Star rating must be between 1 and 5"}), 400

    # Create a new review
    new_review = Review(
        artist_id=artist_id,
        star_rating=star_rating,
        review_text=review_text,
        photo_url=photo_url
    )
    db.session.add(new_review)
    db.session.commit()

    # Update the artist's average rating
    artist = Artist.query.get(artist_id)
    artist.average_rating = db.session.query(func.avg(Review.star_rating)).filter_by(artist_id=artist_id).scalar()
    db.session.commit()

    return jsonify(new_review.to_dict()), 201


@app.get('/api/artists/<int:artist_id>/reviews')
def get_reviews(artist_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    reviews = Review.query.filter_by(artist_id=artist_id).paginate(page=page, per_page=per_page)

    return jsonify({
        "reviews": [review.to_dict() for review in reviews.items],
        "total_items": reviews.total,
        "total_pages": reviews.pages,
        "current_page": reviews.page
    }), 200

@app.patch('/api/reviews/<int:review_id>')
def update_review(review_id):
    review = Review.query.get(review_id)
    if not review:
        return jsonify({"error": "Review not found"}), 404

    data = request.get_json()
    if "star_rating" in data:
        star_rating = data["star_rating"]
        if not (1 <= star_rating <= 5):
            return jsonify({"error": "Star rating must be between 1 and 5"}), 400
        review.star_rating = star_rating

    if "review_text" in data:
        review.review_text = data["review_text"]

    if "photo_url" in data:
        review.photo_url = data["photo_url"]

    db.session.commit()

    # Update artist's average rating
    artist = Artist.query.get(review.artist_id)
    artist.average_rating = db.session.query(func.avg(Review.star_rating)).filter_by(artist_id=review.artist_id).scalar()
    db.session.commit()

    return jsonify(review.to_dict()), 200

@app.delete('/api/reviews/<int:review_id>')
def delete_review(review_id):
    review = Review.query.get(review_id)
    if not review:
        return jsonify({"error": "Review not found"}), 404

    artist_id = review.artist_id
    db.session.delete(review)
    db.session.commit()

    # Update artist's average rating
    artist = Artist.query.get(artist_id)
    artist.average_rating = db.session.query(func.avg(Review.star_rating)).filter_by(artist_id=artist_id).scalar()
    db.session.commit()

    return jsonify({"message": "Review deleted successfully"}), 200


@app.patch('/api/bookings/<int:booking_id>/payment_status')
def update_payment_status(booking_id):
    """Endpoint for updating the payment status of a booking."""
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({"error": "Booking not found"}), 404

    data = request.get_json()
    new_status = data.get("payment_status")

    # Validate the new status
    if new_status not in ["unpaid", "paid"]:
        return jsonify({"error": "Invalid payment status. Must be 'unpaid' or 'paid'"}), 400

    # Update the payment status
    booking.payment_status = new_status
    db.session.commit()

    return jsonify({"message": "Payment status updated successfully", "booking": booking.to_dict()}), 200


#------------------------------------------------------------------------------------------#
class Gallery(db.Model, SerializerMixin):
    __tablename__ = "gallery"

    id = db.Column(db.Integer, primary_key=True)
    artist_id = db.Column(db.Integer, db.ForeignKey("artists.id", name="fk_gallery_artist"), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)  # URL for the image
    caption = db.Column(db.String(255), nullable=True)  # Optional caption
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    artist = db.relationship("Artist", back_populates="gallery")

    serialize_rules = ("-artist.gallery",)

    def to_dict(self):
        photo_dict = super().to_dict()
        photo_dict["created_at"] = format_datetime(self.created_at)  # Use the helper function
        photo_dict["artist_name"] = self.artist.name  # Include the artist's name

        return photo_dict


@app.post('/api/artists/<int:artist_id>/gallery')
@token_required
def upload_photo(current_user, artist_id):
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404


    data = request.get_json()
    image_url = data.get('image_url')
    caption = data.get('caption')

    if not image_url or not is_valid_url(image_url):
        return jsonify({'error': 'Valid image URL is required'}), 400

    new_photo = Gallery(artist_id=artist_id, image_url=image_url, caption=caption)
    db.session.add(new_photo)
    db.session.commit()

    return jsonify(new_photo.to_dict()), 201



@app.get('/api/artists/<int:artist_id>/gallery')
def get_gallery(artist_id):
    """
    Retrieve a paginated list of gallery photos for a specific artist,
    with optional search by caption.
    """
    artist = Artist.query.get(artist_id)
    if not artist:
        return jsonify({'error': 'Artist not found'}), 404

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    search_query = request.args.get("search", "").strip()

    # Base query to filter by artist ID
    query = Gallery.query.filter_by(artist_id=artist_id)

    # Apply caption search if a search query is provided
    if search_query:
        query = query.filter(Gallery.caption.ilike(f"%{search_query}%"))

    # Paginate the results
    photos = query.paginate(page=page, per_page=per_page)

    return jsonify({
        "photos": [photo.to_dict() for photo in photos.items],
        "total": photos.total,
        "page": photos.page,
        "pages": photos.pages
    }), 200


@app.get('/api/galleries')
def get_all_galleries():
    """
    Fetch all galleries with optional pagination.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)

    galleries = Gallery.query.options(joinedload(Gallery.artist)).paginate(page=page, per_page=per_page)

    return jsonify({
        "galleries": [gallery.to_dict() for gallery in galleries.items],
        "total": galleries.total,
        "page": galleries.page,
        "pages": galleries.pages
    }), 200

@app.delete('/api/gallery/<int:photo_id>')
def delete_photo(photo_id):
    photo = Gallery.query.get(photo_id)
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404

    artist = Artist.query.get(photo.artist_id)
    if not artist:
        return jsonify({'error': 'Associated artist not found'}), 404

    # Only the artist or admin can delete photos

    db.session.delete(photo)
    db.session.commit()
    return jsonify({'message': 'Photo deleted successfully'}), 200



#----------------------------------------------------------------------------------#

class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)  # Add email field
    password_hash = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(50), nullable=False)  # 'artist' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    @password.setter
    def password(self, plaintext_password):
        self.password_hash = bcrypt.generate_password_hash(plaintext_password).decode('utf-8')

    def verify_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.password_hash, plaintext_password)
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,  # Include email in the response
            'user_type': self.user_type,
            'created_at': format_datetime(self.created_at) if self.created_at else None,
            'last_login': format_datetime(self.last_login) if self.last_login else None
        }

def validate_password(password):
    """
    Validates the password against security criteria.
    """
    if not password:
        abort(400, description="Password is required.")
    if len(password) < 8:
        abort(400, description="Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        abort(400, description="Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        abort(400, description="Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        abort(400, description="Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        abort(400, description="Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")


def generate_token(payload):
    payload["exp"] = datetime.utcnow() + timedelta(hours=6)  # Extend expiration
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


def is_artist_user():
    return request.user_type == 'artist'

def is_admin_user():
    return request.user_type == 'admin'

@app.post('/api/signup')
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')  # New field
    password = data.get('password')
    user_type = data.get('user_type')  # Should be either 'artist' or 'admin'

    # Validate input
    if not all([username, email, password, user_type]):
        return jsonify({'error': 'Username, email, password, and user type are required.'}), 400
    if user_type not in ['artist', 'admin']:
        return jsonify({'error': 'Invalid user type.'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists.'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists.'}), 400  # Check for email uniqueness

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': 'Invalid email format.'}), 400

    # Validate password strength
    try:
        validate_password(password)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    # Create user
    new_user = User(username=username, email=email, user_type=user_type)
    new_user.password = password

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully!', 'user': new_user.to_dict()}), 201




@app.post('/api/signin')
def signin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return jsonify({'error': 'Invalid username or password.'}), 401
    # Update last_login
    user.last_login = datetime.utcnow()
    db.session.commit()

    # Prepare the payload for the token
    payload = {
        "user_id": user.id,
        "username": user.username,
        "user_type": user.user_type,
        "exp": datetime.utcnow() + timedelta(hours=6)  # Token expiration
    }

    # Generate token
    token = generate_token(payload)

    return jsonify({'message': 'Sign-in successful!', 'token': token, 'user': user.to_dict()}), 200

@app.get('/api/admin-dashboard/activity')
@token_required
def user_activity():
    if not is_admin_user():
        return jsonify({'error': 'Access denied. Admins only.'}), 403

    recent_logins = User.query.order_by(User.last_login.desc()).limit(10).all()
    activity = [
        {
            'user_id': user.id,
            'username': user.username,
            'last_login': format_datetime(user.last_login) if user.last_login else "Never Logged In",
            'user_type': user.user_type
        }
        for user in recent_logins if user.last_login
    ]

    return jsonify({
        'recent_activity': activity
    }), 200


@app.route('/api/artist-dashboard', methods=['GET', 'PATCH'])
@token_required
def artist_dashboard(current_user):  # Accept the current_user argument
    if not is_artist_user():
        return jsonify({'error': 'Access denied. Artists only.'}), 403

    # Fetch the artist's profile
    artist = Artist.query.filter_by(created_by=current_user.id).first()
    if not artist:
        return jsonify({'error': 'Artist profile not found.'}), 404

    if request.method == 'PATCH':
        # Handle profile update
        data = request.get_json()
        if "name" in data:
            artist.name = data["name"]
        if "specialties" in data:
            artist.specialties = data["specialties"]
        if "bio" in data:
            artist.bio = data["bio"]
        if "portfolio" in data:
            artist.portfolio = data["portfolio"]
        if "social_media" in data:
            artist.social_media = data["social_media"]
        if "years_of_experience" in data:
            if isinstance(data["years_of_experience"], int):
                artist.years_of_experience = data["years_of_experience"]
            else:
                return jsonify({"error": "Years of experience must be an integer."}), 400
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully', 'artist': artist.to_dict()}), 200

    # Fetch bookings, reviews, and gallery
    upcoming_bookings = Booking.query.filter(
        Booking.artist_id == artist.id,
        Booking.appointment_date > datetime.now()
    ).order_by(Booking.appointment_date).limit(5).all()

    reviews = Review.query.filter_by(artist_id=artist.id).order_by(Review.created_at.desc()).limit(5).all()
    portfolio_preview = artist.gallery[:5]  # Limit to 5 images for preview

    performance_metrics = {
        'total_bookings': Booking.query.filter_by(artist_id=artist.id).count(),
        'total_earnings': db.session.query(func.sum(Booking.price)).filter_by(artist_id=artist.id).scalar() or 0,
    }

    # Build the response
    dashboard_data = {
        'artist_details': artist.to_dict(),
        'upcoming_bookings': [booking.to_dict() for booking in upcoming_bookings],
        'recent_reviews': [review.to_dict() for review in reviews],
        'portfolio_preview': [photo.to_dict() for photo in portfolio_preview],
        'performance_metrics': performance_metrics,
    }

    return jsonify(dashboard_data), 200


@app.route('/api/admin-dashboard', methods=['GET'])
@token_required
def admin_dashboard(current_user):  # Add current_user parameter
    if not is_admin_user():
        return jsonify({'error': 'Access denied. Admins only.'}), 403

    # Personal Artist Profile (if admin is also an artist)
    artist = Artist.query.filter_by(created_by=current_user.id).first()
    personal_data = None
    if artist:
        # Fetch personal bookings, piercings, reviews, and performance metrics
        upcoming_bookings = Booking.query.filter(
            Booking.artist_id == artist.id,
            Booking.appointment_date > datetime.now()
        ).order_by(Booking.appointment_date).limit(5).all()

        upcoming_piercings = Piercing.query.filter(
            Piercing.artist_id == artist.id,
            Piercing.appointment_date > datetime.now()
        ).order_by(Piercing.appointment_date).limit(5).all()

        recent_reviews = Review.query.filter_by(artist_id=artist.id).order_by(Review.created_at.desc()).limit(5).all()

        performance_metrics = {
            'total_bookings': Booking.query.filter_by(artist_id=artist.id).count(),
            'total_piercings': Piercing.query.filter_by(artist_id=artist.id).count(),
            'total_earnings': (
                db.session.query(func.sum(Booking.price)).filter_by(artist_id=artist.id).scalar() or 0
            ) + (
                db.session.query(func.sum(Piercing.price)).filter_by(artist_id=artist.id).scalar() or 0
            ),
        }

        personal_data = {
            'artist_details': artist.to_dict(),
            'upcoming_bookings': [booking.to_dict() for booking in upcoming_bookings],
            'upcoming_piercings': [piercing.to_dict() for piercing in upcoming_piercings],
            'recent_reviews': [review.to_dict() for review in recent_reviews],
            'performance_metrics': performance_metrics,
        }

    # All Users
    users = User.query.all()
    all_users = [user.to_dict() for user in users]

    # All Bookings
    bookings = Booking.query.options(joinedload(Booking.artist)).all()
    piercings = Piercing.query.options(joinedload(Piercing.artist)).all()
    all_appointments = [
        {
            **booking.to_dict(),
            'artist_name': booking.artist.name if booking.artist else None,
            'type': 'booking',
        }
        for booking in bookings
    ] + [
        {
            **piercing.to_dict(),
            'artist_name': piercing.artist.name if piercing.artist else None,
            'type': 'piercing',
        }
        for piercing in piercings
    ]

    # Platform Metrics
    total_bookings = Booking.query.count()
    total_piercings = Piercing.query.count()
    total_earnings = (
        db.session.query(func.sum(Booking.price)).scalar() or 0
    ) + (
        db.session.query(func.sum(Piercing.price)).scalar() or 0
    )
    average_rating = db.session.query(func.avg(Review.star_rating)).scalar() or 0

    platform_metrics = {
        'total_bookings': total_bookings,
        'total_piercings': total_piercings,
        'total_appointments': total_bookings + total_piercings,
        'total_earnings': total_earnings,
        'average_rating': round(average_rating, 2),
    }

    # Build the response
    dashboard_data = {
        'personal_data': personal_data,
        'users': all_users,
        'appointments': all_appointments,
        'platform_metrics': platform_metrics,
    }

    return jsonify(dashboard_data), 200


@app.patch('/api/users/<int:user_id>')
@token_required
def update_user(current_user, user_id):
    """
    Update a user's details. Only admins or the user themselves can update their details.
    """
    # Fetch the user
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check permissions: Only the user or an admin can edit
    if current_user.user_type != 'admin' and current_user.id != user.id:
        return jsonify({'error': 'Unauthorized access'}), 403

    # Parse the request data
    data = request.get_json()

    # Update fields if provided
    if 'username' in data:
        if User.query.filter(User.username == data['username'], User.id != user.id).first():
            return jsonify({'error': 'Username already exists.'}), 400
        user.username = data['username']
    if 'email' in data:
        if User.query.filter(User.email == data['email'], User.id != user.id).first():
            return jsonify({'error': 'Email already exists.'}), 400
        user.email = data['email']
    if 'password' in data:
        try:
            validate_password(data['password'])  # Validate password strength
            user.password = data['password']
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    if 'user_type' in data:
        if current_user.user_type != 'admin':  # Only admins can change user type
            return jsonify({'error': 'Only admins can change user type.'}), 403
        if data['user_type'] not in ['artist', 'admin']:
            return jsonify({'error': 'Invalid user type.'}), 400
        user.user_type = data['user_type']

    try:
        db.session.commit()
        return jsonify({'message': 'User updated successfully.', 'user': user.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.post('/api/request-password-reset')
def request_password_reset():
    """
    Endpoint to request a password reset. Sends a reset token to the user's email.
    """
    data = request.get_json()
    email = data.get("email")  # Use email instead of username

    if not email:
        return jsonify({"error": "Email is required."}), 400

    user = User.query.filter_by(email=email).first()  # Look up by email
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Generate a secure token
    token = serializer.dumps(user.email, salt="password-reset-salt")
    reset_link = f"http://localhost:5173/reset-password?token={token}"

    # Send the email
    try:
        send_email(
            recipient=user.email,
            subject="Password Reset Request",
            reset_link=reset_link  # Pass only the link
        )
    except Exception as e:
        return jsonify({"error": "Failed to send email.", "details": str(e)}), 500

    return jsonify({"message": "Password reset email sent successfully."}), 200

@app.post('/api/reset-password')
def reset_password():
    """
    Endpoint to reset the user's password using a valid reset token.
    """
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        return jsonify({"error": "Token and new password are required."}), 400

    try:
        # Verify the token
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except Exception as e:
        return jsonify({"error": "Invalid or expired token.", "details": str(e)}), 400

    # Find the user and update their password
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    try:
        validate_password(new_password)  # Ensure the new password meets security criteria
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # Hash the password before saving
    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()

    return jsonify({"message": "Password reset successfully."}), 200



# Helper function to send email (simplified)
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(recipient, subject, reset_link, background_image_url=None):
    """
    Sends an email with improved styling using smtplib.
    """
    # Get environment variables
    sender_email = os.getenv('EMAIL_ADDRESS')
    sender_password = os.getenv('EMAIL_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))  # Default to 587 if not provided

    # Check if essential environment variables are set
    if not all([sender_email, sender_password, smtp_server, smtp_port]):
        raise ValueError("Missing email configuration in environment variables.")

    # Build the HTML body with styling
    html_body = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                color: white;
                line-height: 1.5;
            }}
            .email-container {{
                max-width: 600px;
                margin: 20px auto;
                padding: 20px;
                background: rgba(0, 0, 0, 0.7); /* Semi-transparent black background */
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            .email-header {{
                text-align: center;
                padding: 20px;
            }}
            .email-header h1 {{
                margin: 0;
                font-size: 28px;
                color: #fff;
                text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.8);
            }}
            .email-body {{
                background-image: url('{background_image_url or "https://img.freepik.com/premium-photo/strategic-email-marketing-campaign-pink-envelope-background_952286-14040.jpg"}');
                background-size: cover;
                background-position: center;
                background-repeat: no-repeat;
                padding: 20px;
                font-size: 16px;
                position: relative;
                overflow: hidden;
            }}
            .email-body::before {{
                content: "";
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.6); /* Semi-transparent overlay */
                z-index: 1;
            }}
            .email-body p, .email-body a {{
                position: relative;
                z-index: 2;
                color: #f9f9f9; /* Ensure text color is light */
            }}
            .email-body a {{
                color: #89CFF0; /* Baby blue color for links */
                text-decoration: underline;
                font-weight: bold;
            }}
            .email-footer {{
                text-align: center;
                font-size: 12px;
                color: #aaaaaa;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-header">
                <h1>Ink Haven: Reset Your Password</h1>
            </div>
            <div class="email-body">
                <p>Hello {recipient}! We received your request to reset your password!</p>

                <p>If you did not request this change, you can safely ignore this email.</p>
                                <p>
                    <a href="{reset_link}" target="_blank">Click here to reset your password</a>
                </p>
            </div>
            <div class="email-footer">
                <p>&copy; 2024 Tattoo Parlor. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Set up the MIME structure
    msg = MIMEMultipart("alternative")
    msg["From"] = sender_email
    msg["To"] = recipient
    msg["Subject"] = subject

    # Attach the HTML content
    msg.attach(MIMEText(html_body, "html"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()  # Identify with the server
            server.starttls()  # Upgrade connection to TLS
            server.login(sender_email, sender_password)  # Authenticate
            server.send_message(msg)  # Send the email
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")


@app.get('/api/admin-dashboard/bookings-trends')
@token_required
def monthly_booking_trends(current_user):  # Add current_user parameter
    if not is_admin_user():
        return jsonify({'error': 'Access denied. Admins only.'}), 403

    current_year = datetime.now().year
    trends = db.session.query(
        extract('month', Booking.appointment_date).label('month'),
        func.count(Booking.id).label('total_bookings')
    ).filter(
        extract('year', Booking.appointment_date) == current_year
    ).group_by(
        extract('month', Booking.appointment_date)
    ).order_by('month').all()

    # Ensure `month` is cast to int
    monthly_trends = [
        {'month': calendar.month_name[int(month)], 'total_bookings': total} 
        for month, total in trends
    ]
    return jsonify({
        'year': current_year,
        'monthly_trends': monthly_trends
    }), 200

#------------------------------------------------------------------------------------inquiries#

class Inquiry(db.Model, SerializerMixin):
    __tablename__ = "inquiries"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)  # Optional
    email = db.Column(db.String(255), nullable=False)  # Required
    inquiry = db.Column(db.Text, nullable=False)  # Required inquiry message
    submitted_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    status = db.Column(db.String(50), default="pending", nullable=False)  # New column

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "phone_number": self.phone_number,
            "email": self.email,
            "inquiry": self.inquiry,
            "submitted_at": format_datetime(self.submitted_at),
            "status": self.status,  # Include status in the response
        }

@app.post('/api/inquiries')
def create_inquiry():
    data = request.get_json()

    # Validate required fields
    required_fields = ['name', 'email', 'inquiry']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    # Validate email format
    email = data.get('email')
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    # Create a new inquiry
    new_inquiry = Inquiry(
        name=data.get('name'),
        phone_number=data.get('phone_number'),
        email=email,
        inquiry=data.get('inquiry'),
        status=data.get('status', 'pending'),  # Default to 'pending'
    )

    # Save to database
    try:
        db.session.add(new_inquiry)
        db.session.commit()
        return jsonify(new_inquiry.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.patch('/api/inquiries/<int:inquiry_id>')
@token_required
def update_inquiry(current_user, inquiry_id):
    # Ensure only admin or artist users can update
    if current_user.user_type not in ['admin', 'artist']:
        return jsonify({'error': 'Access denied. Admins and artists only.'}), 403

    inquiry = Inquiry.query.get(inquiry_id)
    if not inquiry:
        return jsonify({'error': 'Inquiry not found.'}), 404

    data = request.get_json()

    # Update fields
    if "status" in data:
        inquiry.status = data["status"]

    try:
        db.session.commit()
        return jsonify(inquiry.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.delete('/api/inquiries/<int:inquiry_id>')
@token_required
def delete_inquiry(current_user, inquiry_id):
    """
    Delete an inquiry. Only accessible by admin or artist users.
    """
    # Ensure the user is authorized
    if current_user.user_type not in ['admin', 'artist']:
        return jsonify({'error': 'Access denied. Admins and artists only.'}), 403

    # Fetch the inquiry
    inquiry = Inquiry.query.get(inquiry_id)
    if not inquiry:
        return jsonify({'error': 'Inquiry not found.'}), 404

    try:
        # Delete the inquiry
        db.session.delete(inquiry)
        db.session.commit()
        return jsonify({'message': 'Inquiry deleted successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.get('/api/inquiries')
@token_required
def get_inquiries(current_user):
    if current_user.user_type not in ['admin', 'artist']:
        return jsonify({'error': 'Access denied. Admins and artists only.'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    inquiries_query = Inquiry.query.order_by(Inquiry.submitted_at.desc()).paginate(page=page, per_page=per_page)

    return jsonify({
        "inquiries": [inquiry.to_dict() for inquiry in inquiries_query.items],
        "total_items": inquiries_query.total,
        "total_pages": inquiries_query.pages,
        "current_page": inquiries_query.page
    }), 200
#----------------------------------------
class GlobalSettings(db.Model, SerializerMixin):
    __tablename__ = "global_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(50), nullable=False, default=False)
@app.route('/api/global-settings/<string:key>', methods=['GET'])
def get_or_create_global_setting(key):
    """
    Fetch the value of a global setting by its key, creating it with a default value if it doesn't exist.
    """
    setting = GlobalSettings.query.filter_by(key=key).first()
    if not setting:
        setting = GlobalSettings(key=key, value="false")  # Default value
        db.session.add(setting)
        db.session.commit()

    return jsonify({key: setting.value == "true"}), 200


@app.route('/api/global-settings/<string:key>', methods=['PATCH'])
def update_global_setting(key):
    """
    Update the value of a global setting by its key.
    """
    # Parse request data
    data = request.get_json()
    new_value = data.get("value")

    if new_value is None:
        return jsonify({'error': 'New value is required.'}), 400

    # Retrieve or create the setting
    setting = GlobalSettings.query.filter_by(key=key).first()
    if not setting:
        setting = GlobalSettings(key=key, value="false")  # Default value
        db.session.add(setting)

    # Update the value
    setting.value = "true" if bool(new_value) else "false"
    db.session.commit()

    return jsonify({'message': 'Setting updated successfully.', key: setting.value == "true"}), 200

#-----------------------------------------------------------------------------------------------------------------------------------
def send_newsletter_email(recipient, subject, body, background_image_url=None):
    """
    Sends a newsletter email with a custom body and optional background image.
    """
    sender_email = os.getenv('EMAIL_ADDRESS')
    sender_password = os.getenv('EMAIL_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))  # Default to 587 if not provided

    if not all([sender_email, sender_password, smtp_server, smtp_port]):
        raise ValueError("Missing email configuration in environment variables.")

    # Build the HTML body with inline styles and simplified structure
    html_body = f"""
    <html>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; line-height: 1.6;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
            <tr>
                <td style="background-color: #222; color: #ffffff; text-align: center; padding: 20px;">
                    <h1 style="margin: 0; font-size: 24px;">{subject}</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px; text-align: left; font-size: 16px; color: #333;">
                    <p style="margin: 0 0 20px;">{body}</p>
                    {f"<img src='{background_image_url}' alt='Newsletter Image' style='max-width: 100%; height: auto; display: block; margin: 10px 0;'>" if background_image_url else ""}
                </td>
            </tr>
            <tr>
                <td style="padding: 10px; background-color: #f4f4f4; text-align: center; font-size: 12px; color: #777;">
                    <p style="margin: 0;">&copy; 2024 Tattoo Parlor. All rights reserved.</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["From"] = f"Newsletter <{sender_email}>"
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Reply-To"] = sender_email

    # Attach the plain text version as a fallback
    text_body = f"{subject}\n\n{body}\n\n© 2024 Tattoo Parlor. All rights reserved."
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"Newsletter sent successfully to {recipient}")
    except Exception as e:
        print(f"Failed to send newsletter to {recipient}: {str(e)}")



class Newsletter(db.Model, SerializerMixin):
    __tablename__ = "newsletters"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    image = db.Column(db.String(255), nullable=True)  # URL or file path for the image
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "image": self.image,
            "body": self.body,
            "created_at": format_datetime(self.created_at)
        }

@app.post('/api/newsletters')
def create_newsletter():
    data = request.get_json()
    title = data.get('title')
    image = data.get('image')
    body = data.get('body')

    if not title or not body:
        return jsonify({'error': 'Title and body are required'}), 400

    newsletter = Newsletter(title=title, image=image, body=body)
    db.session.add(newsletter)
    db.session.commit()

    # Send newsletter to all subscribers
    subscribers = Subscriber.query.all()
    for subscriber in subscribers:
        send_newsletter_email(
            recipient=subscriber.email,
            subject=f"New Newsletter: {title}",
            body=body,
            background_image_url=image
        )

    return jsonify({"message": "Newsletter created and emails sent", "newsletter": newsletter.to_dict()}), 201


@app.get('/api/newsletters')
def get_newsletters():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search_query = request.args.get('search', '').strip()

    query = Newsletter.query

    if search_query:
        query = query.filter(Newsletter.title.ilike(f"%{search_query}%"))

    paginated_newsletters = query.order_by(Newsletter.created_at.desc()).paginate(page=page, per_page=per_page)

    return jsonify({
        "newsletters": [newsletter.to_dict() for newsletter in paginated_newsletters.items],
        "total_items": paginated_newsletters.total,
        "total_pages": paginated_newsletters.pages,
        "current_page": paginated_newsletters.page
    }), 200

@app.delete('/api/newsletters/<int:newsletter_id>')
def delete_newsletter(newsletter_id):
    # Find the newsletter by its ID
    newsletter = Newsletter.query.get(newsletter_id)
    
    if not newsletter:
        return jsonify({"error": "Newsletter not found"}), 404

    # Delete the newsletter
    db.session.delete(newsletter)
    db.session.commit()

    return jsonify({"message": f"Newsletter with ID {newsletter_id} deleted successfully"}), 200



#--------------------------------------------------------------------------------------------------------
class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    subscribed_at = db.Column(db.DateTime, nullable=False, default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "subscribed_at": self.subscribed_at.strftime("%A, %B %d, %Y %I:%M %p")  # Format date safely
        }


@app.post('/api/subscribe')
def subscribe():
    data = request.get_json()
    email = data.get('email')

    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    if Subscriber.query.filter_by(email=email).first():
        return jsonify({"error": "This email is already subscribed"}), 400

    subscriber = Subscriber(email=email)
    db.session.add(subscriber)
    db.session.commit()

    return jsonify({"message": "Subscription successful", "subscriber": subscriber.to_dict()}), 201


@app.get('/api/subscribers')
def get_subscribers():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search_query = request.args.get('search', '', type=str)

    query = Subscriber.query

    if search_query:
        query = query.filter(Subscriber.email.ilike(f"%{search_query}%"))

    paginated_subscribers = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "subscribers": [subscriber.to_dict() for subscriber in paginated_subscribers.items],
        "current_page": paginated_subscribers.page,
        "total_pages": paginated_subscribers.pages
    }), 200


@app.delete('/api/unsubscribe')
def unsubscribe():
    try:
        email = request.args.get('email', type=str)  # Get the email from query parameters
        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Query the subscriber by email
        subscriber = Subscriber.query.filter_by(email=email).first()
        if not subscriber:
            return jsonify({"error": "Subscriber not found"}), 404

        # Delete the subscriber from the database
        db.session.delete(subscriber)
        db.session.commit()

        print(f"Unsubscribed email: {email}")  # Log the unsubscribed email
        return jsonify({"message": "Successfully unsubscribed"}), 200

    except Exception as e:
        print(f"Error: {str(e)}")  # Log any unexpected errors
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True)