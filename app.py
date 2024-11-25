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
CORS(app, supports_credentials=True, origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_headers=["Content-Type", "Authorization"])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tattoo.db'  # Change to your database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
    public_endpoints = ['signup', 'signin', 'reset_password', 'send_message', 'get_booking','get_average_rating', 'artists' ,'get_artist_by_id','get_artist_bookings','create_review','get_reviews','get_gallery', 'bookings', 'create_booking', 'get_all_galleries','create_inquiry']
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
        print(f"Formatting booking_date: {self.booking_date}")
        print(f"Formatting appointment_date: {self.appointment_date}")
        
        booking_dict = super().to_dict()
        booking_dict["booking_date"] = format_datetime(self.booking_date)
        booking_dict["appointment_date"] = format_datetime(self.appointment_date)
        print(f"Formatted dictionary: {booking_dict}")
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
    per_page = request.args.get('per_page', 10, type=int)

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
@token_required
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
        # Fetch personal bookings, reviews, and performance metrics
        upcoming_bookings = Booking.query.filter(
            Booking.artist_id == artist.id,
            Booking.appointment_date > datetime.now()
        ).order_by(Booking.appointment_date).limit(5).all()
        
        recent_reviews = Review.query.filter_by(artist_id=artist.id).order_by(Review.created_at.desc()).limit(5).all()
        
        performance_metrics = {
            'total_bookings': Booking.query.filter_by(artist_id=artist.id).count(),
            'total_earnings': db.session.query(func.sum(Booking.price)).filter_by(artist_id=artist.id).scalar() or 0,
        }
        
        personal_data = {
            'artist_details': artist.to_dict(),
            'upcoming_bookings': [booking.to_dict() for booking in upcoming_bookings],
            'recent_reviews': [review.to_dict() for review in recent_reviews],
            'performance_metrics': performance_metrics,
        }

    # All Users
    users = User.query.all()
    all_users = [user.to_dict() for user in users]

    # All Bookings
    bookings = Booking.query.options(joinedload(Booking.artist)).all()
    all_bookings = [
        {
            **booking.to_dict(),
            'artist_name': booking.artist.name if booking.artist else None
        }
        for booking in bookings
    ]

    # Platform Metrics
    total_bookings = Booking.query.count()
    total_earnings = db.session.query(func.sum(Booking.price)).scalar() or 0
    average_rating = db.session.query(func.avg(Artist.average_rating)).scalar() or 0

    platform_metrics = {
        'total_bookings': total_bookings,
        'total_earnings': total_earnings,
        'average_rating': round(average_rating, 2),
    }

    # Build the response
    dashboard_data = {
        'personal_data': personal_data,
        'users': all_users,
        'bookings': all_bookings,
        'platform_metrics': platform_metrics,
    }

    return jsonify(dashboard_data), 200



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
    reset_link = f"http://yourfrontend.com/reset-password?token={token}"

    # Send the email using EmailJS or a similar service
    try:
        send_email(
            recipient=user.email,
            subject="Password Reset Request",
            body=f"Click the link to reset your password: {reset_link}"
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

    user.password = new_password
    db.session.commit()

    return jsonify({"message": "Password reset successfully."}), 200


# Helper function to send email (simplified)
def send_email(recipient, subject, body):
    """
    Sends an email using smtplib (simplified implementation).
    Replace with your actual email service provider's logic.
    """
    sender_email = "gottabookemall2024@gmail.com"
    sender_password = "your-email-password"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)


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

    monthly_trends = [
        {'month': calendar.month_name[month], 'total_bookings': total} 
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


if __name__ == "__main__":
    app.run(debug=True)