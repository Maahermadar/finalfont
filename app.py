from flask import Flask, render_template, request, redirect, url_for, send_from_directory, send_file,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from datetime import date
import os
import pandas as pd
import io
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import logout_user
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
from flask import jsonify
from sqlalchemy import func, case
from sqlalchemy.orm import joinedload
from flask import request, redirect, url_for, flash
from datetime import date
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from supabase import create_client, Client  # 🆕 Added for Supabase Storage
from werkzeug.utils import secure_filename
from flask import Flask
from supabase import create_client, Client
from datetime import date
from postgrest import APIError
from flask import send_file
from io import BytesIO
from flask import (  request, redirect, url_for, flash, jsonify, session)
from flask_caching import Cache
from flask import request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import os
from sqlalchemy.exc import IntegrityError
from flask import request, redirect, url_for, flash
from datetime import date
import pandas as pd
import json
from flask_login import UserMixin

from flask import request, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user, login_user
from werkzeug.utils import secure_filename

from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask import redirect, url_for
from docx import Document
from docx.shared import Inches
from sqlalchemy.orm import joinedload, aliased, foreign
from sqlalchemy import func, or_, and_, desc, asc
from functools import wraps
from flask import abort
import re
import pytz
import time
from markupsafe import Markup
from flask import request, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from flask_login import LoginManager

def get_proxy_url(path):
    # If the path is already a URL or None, return as is
    if not path:
        return ""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    # Otherwise, serve from your Flask static/profile image route
    return url_for("serve_profile_image", filename=path)

def normalize_episode(ep):
    if not ep:
        return ''
    
    ep_str = str(ep)
    
    # Translation table for Arabic-Indic numerals to ASCII digits
    arabic_to_english = str.maketrans('٠١٢٣٤٥٦٧٨٩', '0123456789')
    ep_str = ep_str.translate(arabic_to_english)
    
    # Keep only numeric characters (now that Arabic ones are converted)
    ep_num_str = re.sub(r'[^0-9]', '', ep_str)

    if not ep_num_str:
        return ''

    # Convert to int to remove leading zeros, then back to string.
    return str(int(ep_num_str))

def episode_sort_key(ep_str):
    """
    Sorting key for episode strings. Extracts the number.
    Returns a large number for invalid/empty strings to sort them last.
    """
    if not ep_str:
        return 99999
    numeric_part = re.sub(r'[^0-9]', '', str(ep_str))
    if not numeric_part:
        return 99999
    return int(numeric_part)

def roles_required(*roles):
    """
    Decorator that checks if a user has one of the specified roles.
    Returns a JSON error for AJAX requests or flashes and redirects for standard requests.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            # Check if user is authenticated
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            # Check if user has the required role
            if current_user.role not in roles:
                message = "You don't have permission to perform this action."
                # For fetch/AJAX requests, return a JSON error
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
                   request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                    return jsonify(success=False, error=message, message=message), 403
                
                # For standard page navigation, flash a message and redirect
                flash(message, 'danger')
                return redirect(request.referrer or url_for('dashboard_home'))

            # If all checks pass, proceed to the route
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

app = Flask(__name__)
app.jinja_env.globals['get_proxy_url'] = get_proxy_url
app.jinja_env.add_extension('jinja2.ext.do')
app.jinja_env.globals['timedelta'] = timedelta

@app.template_filter('localtime')
def localtime_filter(dt, tz_name='Africa/Nairobi'):
    """Converts a naive UTC datetime object to a local timezone."""
    if not dt:
        return ""
    local_tz = pytz.timezone(tz_name)
    # Assuming dt is a naive datetime object representing UTC time
    return pytz.utc.localize(dt).astimezone(local_tz)

@app.template_filter('a_day_in_the_past')
def a_day_in_the_past_filter(dt):
    """Returns the date part of a datetime object for comparison."""
    if isinstance(dt, datetime):
        return dt.date()
    return dt

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'sourceuploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config['COMMENT_UPLOAD_FOLDER'] = os.path.join('static', 'comments')
os.makedirs(app.config['COMMENT_UPLOAD_FOLDER'], exist_ok=True)

app.config['COMMENT_PHOTOS_FOLDER'] = os.path.join('static', 'comment_photos')
os.makedirs(app.config['COMMENT_PHOTOS_FOLDER'], exist_ok=True)





app.secret_key = 'mhr..0011'
app.config['CACHE_TYPE'] = 'simple'  # You can switch to 'filesystem' if needed
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # Cache images for 5 minutes (300 seconds)
cache = Cache(app)

@app.template_filter('basename')
def basename_filter(path):
    if path:
        return os.path.basename(path)
    return ""



app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:0099..@localhost/font_database'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)






class QuickReviewSession(db.Model):
    __tablename__ = 'quick_review_session'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    items = db.relationship('QuickReviewItem', backref='session', cascade="all, delete-orphan")

    @property
    def item_count(self):
        return len(self.items)



class AdminUser(db.Model):
    __tablename__ = 'admin'  # This creates a table named "admin"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)




class QuickReviewItem(db.Model):
    __tablename__ = 'quick_review_item'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('quick_review_session.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    episode = db.Column(db.String(100), nullable=False)
    is_reviewed = db.Column(db.Boolean, default=False)
    review_date = db.Column(db.DateTime, nullable=True)
    comment_file_name = db.Column(db.String(255))

    def to_dict(self):
        return {
            "id": self.id,
            "subject": self.subject,
            "episode": self.episode,
            "is_reviewed": self.is_reviewed
        }
    


class ReviewCommentLog(db.Model):
    __tablename__ = 'review_comments_log'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    episode = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    docx_file_path = db.Column(db.String(200), nullable=False, unique=True)

    

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    username = db.Column(db.String(50))
    action = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20))  # e.g., 'Success' or 'Denied'
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    


# ── EditorHandoff model ────────────────────────────────────────────────────────
class EditorHandoff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    episode = db.Column(db.String(50), nullable=False)
    chapter = db.Column(db.String(200), nullable=True)  # <-- Add this
    progress = db.Column(db.String(50), nullable=False)
    date_assigned = db.Column(db.String(20), nullable=False)
    editor_id = db.Column(db.Integer, db.ForeignKey('editor.id'), nullable=False)

      # 🔥 Add this line to define the relationship
    editor = db.relationship('Editor', backref='handoffs')



class RawVideo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    chapter = db.Column(db.String(200), nullable=True)
    episode = db.Column(db.String(50), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="Not Assigned")
    editor_id = db.Column(db.Integer, db.ForeignKey('editor.id'), nullable=True)  # 👈 Add this
    editor = db.relationship('Editor', backref='raw_videos')




class Editor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)  # optional: path to their avatar


def seed_editors():
    editor_names = ["maaher", "mohamed", "yakoub", "raxma"]
    for name in editor_names:
        # 🔥 Match without case sensitivity
        existing = Editor.query.filter(func.lower(Editor.name) == name.lower()).first()
        if not existing:
            db.session.add(Editor(name=name))
    db.session.commit()

with app.app_context():
    seed_editors()

    



# Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='editor')  # Roles: 'editor', 'supervisor', 'manager', 'operator_admin'
    profile_picture = db.Column(db.String(200), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    password_reset_required = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def is_admin(self):
        return self.role == 'operator_admin'



class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('supervisor.id'), nullable=True)



class Supervisor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)

    subjects = db.relationship('Subject', backref='supervisor')


class SupervisorSchedule(db.Model):
    __tablename__ = 'supervisor_schedule'
    id = db.Column(db.Integer, primary_key=True)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('supervisor.id', ondelete='CASCADE'), nullable=False)
    day_of_week = db.Column(db.String(10), nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    supervisor = db.relationship('Supervisor', backref='schedule_entries')

    def to_dict(self):
        return {
            'id': self.id,
            'supervisor_id': self.supervisor_id,
            'supervisor_name': self.supervisor.name,
            'day_of_week': self.day_of_week,
            'start_time': self.start_time.strftime('%H:%M'),
            'end_time': self.end_time.strftime('%H:%M')
        }


class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    chapter = db.Column(db.String(200), nullable=False)
    episode = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="Under Review")
    date = db.Column(db.String(20), nullable=False)
    file_path = db.Column(db.String(200), nullable=True)

    def to_dict(self):
         return {
            "id": self.id,
            "subject": self.subject,
            "episode": self.episode,
            "status": self.status
            # Add other relevant fields
        }
    
    # ✅ Named Foreign Key
    editor_id = db.Column(db.Integer, db.ForeignKey('editor.id', name='fk_video_editor_id'), nullable=True)
    editor = db.relationship('Editor', backref='videos')

    # ✅ Relationship to Subject for easier joins
    subject_obj = db.relationship(
        'Subject',
        primaryjoin='foreign(Video.subject) == Subject.name',
        backref='videos',
        uselist=False
    )

class TimestampComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    minutes = db.Column(db.Integer, nullable=False)
    seconds = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    photo_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    video = db.relationship('Video', backref=db.backref('timestamp_comments', lazy=True, cascade="all, delete-orphan"))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('review_comments_log.id'), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    message = db.Column(db.String(255), nullable=True)
    notification_type = db.Column(db.String(50), nullable=False, default='comment')

    user = db.relationship('Users', backref='notifications')
    comment = db.relationship('ReviewCommentLog', backref='notifications')

class SourceMaterial(db.Model):
    __tablename__ = 'source_material'

    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    chapter = db.Column(db.String(200), nullable=False)
    episode = db.Column(db.String(50), nullable=False)
    ppt_filename = db.Column(db.String(200))  # saved filename like 'chapter1.pptx'
    supervisor_id = db.Column(db.Integer, db.ForeignKey('supervisor.id'))
    supervisor = db.relationship("Supervisor", backref="materials")


with app.app_context():
    db.create_all()

    def seed_subjects():
        subjects = ["Math", "Physics", "Biology", "Chemistry", "Geography", "English"]
        for name in subjects:
            if not Subject.query.filter_by(name=name).first():
                db.session.add(Subject(name=name))
        db.session.commit()

    seed_subjects()

@app.route('/')
def index():
    return redirect(url_for('login'))







@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form.get('role', 'editor')  # Default to 'editor'

        # 🔐 Hash the password for security
        hashed_pw = generate_password_hash(password)

        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return render_template('signup.html', error='Username already exists')

        # Create user with the selected role
        new_user = Users(username=username, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('User account created successfully! Please sign in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')




from flask_login import login_user
from werkzeug.security import check_password_hash  # if you're hashing passwords



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = Users.query.filter_by(username=username).first()

        # ✅ Check hashed password
        if user and check_password_hash(user.password, password):
            login_user(user)

            # --- Password Reset Check ---
            if user.password_reset_required:
                session['force_password_reset_user_id'] = user.id
                return redirect(url_for('force_password_reset'))

            # --- [NEW] Schedule Reminder Notification ---
            if user.role == 'supervisor':
                today_day_name = datetime.now(timezone.utc).strftime('%A')
                supervisor_profile = Supervisor.query.filter(func.lower(Supervisor.name) == func.lower(user.username)).first()
                
                if supervisor_profile:
                    todays_schedule_exists = SupervisorSchedule.query.filter_by(
                        supervisor_id=supervisor_profile.id,
                        day_of_week=today_day_name
                    ).first()

                    if todays_schedule_exists:
                        # Check for an existing reminder for today to prevent duplicates
                        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                        
                        existing_notification_today = Notification.query.filter(
                            Notification.user_id == user.id,
                            Notification.notification_type == 'schedule_reminder',
                            Notification.created_at >= today_start
                        ).first()

                        if not existing_notification_today:
                            notification_message = f"Reminder: Today ({today_day_name}) is a scheduled review day for you."
                            notification = Notification(
                                user_id=user.id,
                                message=notification_message,
                                notification_type='schedule_reminder'
                            )
                            db.session.add(notification)

            # ✅ Log login once per session and commit any new notifications
            if not session.get('login_logged'):
                log = ActivityLog(
                    user_id=user.id,
                    username=user.username,
                    action="Logged in",
                    status="Success",
                    is_admin=user.is_admin,
                    timestamp=datetime.now(timezone.utc)
                )
                db.session.add(log)
            
            try:
                db.session.commit()
                if not session.get('login_logged'):
                    session['login_logged'] = True
            except Exception as e:
                db.session.rollback()
                flash("There was an error during login. Please try again.", "danger")
                print(f"Login error: {e}") # Log error
                return redirect(url_for('login'))
            
            # Role-based redirect
            if user.role in ['operator_admin', 'manager']:
                return redirect(url_for('dashboard_home'))
            elif user.role == 'supervisor':
                return redirect(url_for('review')) # Or whatever their default page is
            elif user.role == 'editor':
                return redirect(url_for('editors')) # Or their specific dashboard
            
            return redirect(url_for('dashboard_home'))

        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')





from collections import defaultdict
from sqlalchemy import func





@app.route('/dashboard_base')
def base():
    return render_template("dashboard_base.html",)




@app.route('/dashboard_home')
@login_required
@roles_required('operator_admin', 'manager', 'supervisor', 'editor')
def dashboard_home():
    # --- Date calculations for queries ---
    thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')
    today_day_name = datetime.now(timezone.utc).strftime('%A')

    # --- Check user role for content filtering ---
    user_role = current_user.role
    show_shooting_progress = user_role in ['operator_admin', 'manager']
    show_editors_in_team = user_role in ['operator_admin', 'manager']

    # --- Shooting Progress (only for admins/managers) ---
    shooting_progress_data = []
    total_shot_count = 0
    total_planned_episodes = 0
    overall_shooting_percentage = 0
    shot_statistics = {}
    
    if show_shooting_progress:
        # --- New, more robust shooting progress logic ---
        all_subjects = Subject.query.order_by(Subject.name).all()
        
        # Pre-fetch all unique episodes from all tables to reduce DB queries
        all_raw_episodes = db.session.query(RawVideo.subject, RawVideo.episode).distinct().all()
        all_handoff_episodes = db.session.query(EditorHandoff.subject, EditorHandoff.episode).distinct().all()
        all_video_episodes = db.session.query(Video.subject, Video.episode).distinct().all()

        # Group episodes by subject for easy lookup
        episodes_by_subject = defaultdict(set)
        for subject, episode in all_raw_episodes:
            episodes_by_subject[subject].add(normalize_episode(episode))
        for subject, episode in all_handoff_episodes:
            episodes_by_subject[subject].add(normalize_episode(episode))
        for subject, episode in all_video_episodes:
            episodes_by_subject[subject].add(normalize_episode(episode))

        subject_episode_map = {
            'Chemistry': 26, 'Math': 30, 'English': 30, 'Geography': 21
        }

        for subject in all_subjects:
            # Use hardcoded map for total episodes
            total_episodes = subject_episode_map.get(subject.name, 25)

            shot_count = len(episodes_by_subject.get(subject.name, set()))
            percentage = (shot_count / total_episodes) * 100 if total_episodes > 0 else 0
            
            color_class = 'green' if percentage >= 80 else 'yellow' if percentage >= 40 else 'red'
            # Define a color for the inline style
            color_hex = '#28a745' if percentage >= 80 else '#ffc107' if percentage >= 40 else '#dc3545'

            shooting_progress_data.append({
                'subject': subject.name,
                'shot_count': shot_count,
                'total_episodes': total_episodes,
                'percentage': round(percentage),
                'color_class': color_class,
                'color': color_hex
            })
            
            total_planned_episodes += total_episodes
            total_shot_count += shot_count  # Add this subject's shot count to the total
        
        shooting_progress_data.sort(key=lambda x: x['percentage'], reverse=True)
        
        # Calculate overall shooting percentage using the corrected total shot count
        if total_planned_episodes > 0:
            overall_shooting_percentage = round((total_shot_count / total_planned_episodes) * 100)

        # --- Calculate detailed statistics for shot videos ---
        if total_shot_count > 0:
            # Count approved videos
            approved_videos_count = Video.query.filter(Video.status == 'Approved').count()
            
            # Count unassigned raw videos
            unassigned_raw_count_total = RawVideo.query.filter(RawVideo.status == 'Not Assigned').count()
            
            # Count re-editing videos (pending status)
            re_editing_count = Video.query.filter(Video.status == 'Pending').count()
            
            # Count under review videos
            under_review_count = Video.query.filter(Video.status == 'Under Review').count()
            
            # Count ongoing handoffs
            ongoing_handoffs_count = EditorHandoff.query.filter(EditorHandoff.progress == 'Ongoing').count()
            
            # Calculate percentages
            approved_percentage = round((approved_videos_count / total_shot_count) * 100)
            unassigned_percentage = round((unassigned_raw_count_total / total_shot_count) * 100)
            re_editing_percentage = round((re_editing_count / total_shot_count) * 100)
            under_review_percentage = round((under_review_count / total_shot_count) * 100)
            ongoing_percentage = round((ongoing_handoffs_count / total_shot_count) * 100)
            
            shot_statistics = {
                'approved': {'count': approved_videos_count, 'percentage': approved_percentage},
                'unassigned': {'count': unassigned_raw_count_total, 'percentage': unassigned_percentage},
                're_editing': {'count': re_editing_count, 'percentage': re_editing_percentage},
                'under_review': {'count': under_review_count, 'percentage': under_review_percentage},
                'ongoing': {'count': ongoing_handoffs_count, 'percentage': ongoing_percentage}
            }
        else:
            shot_statistics = {
                'approved': {'count': 0, 'percentage': 0},
                'unassigned': {'count': 0, 'percentage': 0},
                're_editing': {'count': 0, 'percentage': 0},
                'under_review': {'count': 0, 'percentage': 0},
                'ongoing': {'count': 0, 'percentage': 0}
            }

    # --- Panel 1: Action Items ---
    pending_reviews = db.session.query(
        Video.subject, func.count(Video.id)
    ).filter(Video.status == 'Pending').group_by(Video.subject).order_by(func.count(Video.id).desc()).all()

    unassigned_raw_count = RawVideo.query.filter_by(status='Not Assigned').count()
    
    # Group unassigned raw videos by subject
    unassigned_by_subject = db.session.query(
        RawVideo.subject, func.count(RawVideo.id).label('count')
    ).filter(RawVideo.status == 'Not Assigned').group_by(RawVideo.subject).order_by(func.count(RawVideo.id).desc()).all()
    
    submissions_awaiting_approval_count = ReviewSubmission.query.filter_by(status='pending').count()

    # --- Panel 2: Latest Activity ---
    last_added_video = RawVideo.query.options(
        joinedload(RawVideo.editor)
    ).order_by(RawVideo.date.desc(), RawVideo.id.desc()).first()
    
    last_approved_video = Video.query.options(
        joinedload(Video.subject_obj).joinedload(Subject.supervisor)
    ).filter(Video.status == 'Approved').order_by(Video.date.desc(), Video.id.desc()).first()
    
    today_date = date.today()
    local_tz = pytz.timezone('Africa/Nairobi') # Use the same timezone as the filter
    now_local = datetime.now(timezone.utc).replace(tzinfo=pytz.utc).astimezone(local_tz)
    today_day_name = now_local.strftime('%A')
    now_time = now_local.time()

    # --- Corrected On-Duty Supervisors Query ---
    local_tz = pytz.timezone('Africa/Nairobi')
    now_local = datetime.now(timezone.utc).replace(tzinfo=pytz.utc).astimezone(local_tz)
    today_day_name = now_local.strftime('%A')
    now_time = now_local.time()

    # Get all of today's shifts to handle upcoming/ended statuses
    on_duty_today = SupervisorSchedule.query.join(Supervisor).filter(
        SupervisorSchedule.day_of_week == today_day_name
    ).options(joinedload(SupervisorSchedule.supervisor)).order_by(SupervisorSchedule.start_time).all()

    # Add start and end timestamps for JS
    for schedule in on_duty_today:
        naive_start_datetime = datetime.combine(now_local.date(), schedule.start_time)
        aware_start_datetime = local_tz.localize(naive_start_datetime)
        schedule.start_datetime_ts = int(aware_start_datetime.timestamp())

        naive_end_datetime = datetime.combine(now_local.date(), schedule.end_time)
        aware_end_datetime = local_tz.localize(naive_end_datetime)
        schedule.end_datetime_ts = int(aware_end_datetime.timestamp())

    latest_submission = ReviewSubmission.query.options(
        joinedload(ReviewSubmission.comment_log),
        joinedload(ReviewSubmission.submitted_by)
    ).order_by(ReviewSubmission.submitted_at.desc()).first()

    # --- Panel 3: Team & Performance ---
    editor_leaderboard = []
    if show_editors_in_team:
        editor_leaderboard = db.session.query(
            Editor.name,
            Editor.profile_picture,
            func.count(Video.id).label('approved_count')
        ).join(Video, Editor.id == Video.editor_id)\
         .filter(Video.status == 'Approved', Video.date >= thirty_days_ago)\
         .group_by(Editor.id, Editor.name, Editor.profile_picture)\
         .order_by(desc('approved_count'))\
         .limit(3).all()

    supervisor_leaderboard = db.session.query(
        Supervisor.name,
        Supervisor.profile_picture,
        func.count(Video.id).label('approved_count')
    ).join(Video.subject_obj).join(Subject.supervisor)\
     .filter(Video.status == 'Approved', Video.date >= thirty_days_ago)\
     .group_by(Supervisor.id, Supervisor.name, Supervisor.profile_picture)\
     .order_by(desc('approved_count'))\
     .limit(3).all()

    # Get the max approvals for the progress bar calculation
    max_approvals = editor_leaderboard[0].approved_count if editor_leaderboard else 1

    active_subjects_query = db.session.query(
        Video.subject,
        func.count(Video.id).label('weekly_approved_count')
    ).filter(
        Video.status == 'Approved',
        Video.date >= seven_days_ago  # Comparing date objects
    ).group_by(Video.subject).order_by(desc('weekly_approved_count')).limit(2).all()
    
    active_subjects_data = [{
        'subject': r.subject,
        'weekly_approved_count': r.weekly_approved_count
    } for r in active_subjects_query]

    # --- Get recent unassigned videos specifically ---
    recent_unassigned = RawVideo.query.filter_by(status='Not Assigned').order_by(RawVideo.date.desc(), RawVideo.id.desc()).limit(3).all()
    recent_unassigned_data = [
        {
            'name': f"{video.subject} - Ep {video.episode}",
            'date': video.date
        } for video in recent_unassigned
    ]

    # --- Personalized On-Duty Supervisors for current supervisor ---
    local_tz = pytz.timezone('Africa/Nairobi')
    now_local = datetime.now(timezone.utc).replace(tzinfo=pytz.utc).astimezone(local_tz)
    today_day_name = now_local.strftime('%A')
    now_time = now_local.time()

    # Get all of today's shifts to handle upcoming/ended statuses
    on_duty_today = SupervisorSchedule.query.join(Supervisor).filter(
        SupervisorSchedule.day_of_week == today_day_name
    ).options(joinedload(SupervisorSchedule.supervisor)).order_by(SupervisorSchedule.start_time).all()

    # Personalize for supervisors
    current_supervisor = None
    if user_role == 'supervisor':
        current_supervisor = Supervisor.query.filter(func.lower(Supervisor.name) == func.lower(current_user.username)).first()

    # Add start and end timestamps for JS and personalize names
    for schedule in on_duty_today:
        naive_start_datetime = datetime.combine(now_local.date(), schedule.start_time)
        aware_start_datetime = local_tz.localize(naive_start_datetime)
        schedule.start_datetime_ts = int(aware_start_datetime.timestamp())

        naive_end_datetime = datetime.combine(now_local.date(), schedule.end_time)
        aware_end_datetime = local_tz.localize(naive_end_datetime)
        schedule.end_datetime_ts = int(aware_end_datetime.timestamp())
        
        # Personalize name for current supervisor
        if current_supervisor and schedule.supervisor_id == current_supervisor.id:
            schedule.personalized_name = "You"
            schedule.is_current_user = True
        else:
            schedule.personalized_name = schedule.supervisor.name
            schedule.is_current_user = False

    # --- Top Summary Boxes (existing logic) ---
    total_subjects = Subject.query.count()
    pending_count = Video.query.filter_by(status="Pending").count()
    review_count = Video.query.filter_by(status="Under Review").count()
    approved_count = Video.query.filter_by(status="Approved").count()

    return render_template(
        "dashboard_home.html",
        # Top boxes
        total_subjects=total_subjects,
        pending_count=pending_count,
        review_count=review_count,
        approved_count=approved_count,
        # Action Items
        pending_reviews=pending_reviews,
        unassigned_raw_count=unassigned_raw_count,
        unassigned_by_subject=unassigned_by_subject,
        submissions_awaiting_approval_count=submissions_awaiting_approval_count,
        # Latest Activity
        last_added_video=last_added_video,
        last_approved_video=last_approved_video,
        on_duty_today=on_duty_today,
        latest_submission=latest_submission,
        # Team & Performance
        editor_leaderboard=editor_leaderboard,
        supervisor_leaderboard=supervisor_leaderboard,
        max_approvals=max_approvals,
        active_subjects=active_subjects_data,
        recent_unassigned_data=recent_unassigned_data,
        # Shooting Progress
        shooting_progress_data=shooting_progress_data,
        total_shot_count=total_shot_count,
        total_planned_episodes=total_planned_episodes,
        overall_shooting_percentage=overall_shooting_percentage,
        shot_statistics=shot_statistics,
        # Role-based flags
        user_role=user_role,
        show_shooting_progress=show_shooting_progress,
        show_editors_in_team=show_editors_in_team,
        # General
        current_page='home'
    )





# app.py

from flask import (
    render_template,
    request,
    session,
    redirect,
    url_for
)








from flask import request, render_template
from flask_login import login_required
from sqlalchemy.orm import aliased


@app.route('/review')
@login_required
@roles_required('operator_admin', 'manager', 'supervisor')
def review():
    # Use joinedload for a more robust query that relies on model relationships
    videos = Video.query.options(
        joinedload(Video.editor),
        joinedload(Video.subject_obj).joinedload(Subject.supervisor)
    ).order_by(Video.date.desc()).all()

    # Prepare data for JSON serialization
    videos_data = []
    for video in videos:
        # Explicitly get editor and supervisor from the video object's relationships
        editor = video.editor
        supervisor = video.subject_obj.supervisor if video.subject_obj else None

        editor_data = {
            'name': editor.name if editor else 'Unassigned',
            'profile_picture': url_for('serve_profile_image', filename=editor.profile_picture if editor and editor.profile_picture else 'default.png')
        }
        supervisor_data = {
            'name': supervisor.name if supervisor else 'Unassigned',
            'profile_picture': url_for('serve_profile_image', filename=supervisor.profile_picture if supervisor and supervisor.profile_picture else 'default.png')
        }
        
        videos_data.append({
            'id': video.id,
            'subject': video.subject,
            'chapter': video.chapter or '',
            'episode': video.episode,
            'date': video.date or '',
            'status': video.status,
            'file_path': video.file_path or '',
            'editor': editor_data,
            'supervisor': supervisor_data,
        })

    # Data for filter dropdowns
    subjects = [s.name for s in Subject.query.order_by(Subject.name).all()]
    statuses = [s[0] for s in db.session.query(Video.status).distinct().order_by(Video.status).all() if s[0]]

    return render_template(
        "dashboard_review.html",
        videos=videos_data,
        subjects=subjects,
        statuses=statuses
    )





@app.route('/approval')
def approval():
    subject_filter = request.args.get('subject')
    page = request.args.get('page', 1, type=int)

    # Base query for approved videos, joining with Editor to fetch the name efficiently
    approved_videos_query = Video.query.options(
        joinedload(Video.editor)
    ).filter(
        Video.status == 'Approved'
    ).order_by(Video.date.desc())

    if subject_filter:
        approved_videos_query = approved_videos_query.filter(Video.subject == subject_filter)
    
    # Paginate the results
    videos_pagination = approved_videos_query.paginate(page=page, per_page=10, error_out=False)

    # Fetch all subject names for the filter dropdown
    subjects = [s.name for s in Subject.query.order_by(Subject.name).all()]

    # Calculate the count of approved videos for each subject for the download modal
    approved_counts_query = db.session.query(
        Video.subject,
        func.count(Video.id)
    ).filter(
        Video.status == 'Approved'
    ).group_by(Video.subject).all()
    
    approved_counts = {subject: count for subject, count in approved_counts_query}

    return render_template('approval.html',
                           videos=videos_pagination,
                           subjects=subjects,
                           approved_counts=approved_counts,
                           selected_subject=subject_filter,
                           current_page='approval')
                           
@app.route('/download_video/<subject>/<chapter>/<episode>')
def download_video(subject, chapter, episode):
    # This route appears to be unused, but keeping it for now.
    # The template now uses `download_file`.
    video = Video.query.filter_by(subject=subject, chapter=chapter, episode=episode).first_or_404()
    
    if video.file_path:
        try:
            return send_from_directory(
                os.path.join(app.root_path, 'static', 'documentuploads'),
                video.file_path,
                as_attachment=True
            )
        except FileNotFoundError:
            flash(f"File not found for {subject} {episode}.", "danger")
    else:
        flash(f"No file associated with {subject} {episode}.", "info")
        
    return redirect(url_for('approval'))



@app.route('/add_video', methods=['POST'])
@login_required
@roles_required('operator_admin')
def add_video():
    subject = request.form['subject']
    chapter = request.form['chapter']
    episode = request.form['episode']
    date = request.form['date']
    status = request.form['status']

    file_path = None
    if status == "Pending" and 'file_upload' in request.files:
        uploaded_file = request.files['file_upload']
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join('static', 'documentuploads', filename)
            uploaded_file.save(filepath)
            file_path = filename

    new_video = Video(
        subject=subject,
        chapter=chapter,
        episode=episode,
        date=date,
        status=status,
        file_path=file_path
    )
    db.session.add(new_video)
    db.session.commit()

    return redirect(url_for('review'))


@app.route('/edit_video/<int:video_id>', methods=['GET', 'POST'])
@login_required
@roles_required('operator_admin')
def edit_video(video_id):
    video = Video.query.get_or_404(video_id)

    if request.method == 'POST':
        old_subject = video.subject
        old_episode = video.episode

        new_subject = request.form['subject']
        new_chapter = request.form['chapter']
        new_episode = request.form['episode']
        new_date = request.form['date']
        new_status = request.form['status']

        video.subject = new_subject
        video.chapter = new_chapter
        video.episode = new_episode
        video.date = new_date

        # Optional file upload
        if 'file_upload' in request.files:
            uploaded_file = request.files['file_upload']
            if uploaded_file and uploaded_file.filename:
                filename = secure_filename(uploaded_file.filename)
                filepath = os.path.join('static', 'documentuploads', filename)
                uploaded_file.save(filepath)
                video.file_path = filename

        # Update progress in EditorHandoff if status changes
        if video.status != new_status:
            video.status = new_status
            reverse_sync_map = {
                'Approved': 'Approved',
                'Pending': 'Re-editing',
                'Under Review': 'Finished'
            }
            new_progress = reverse_sync_map.get(new_status)
            if new_progress:
                handoff = EditorHandoff.query.filter_by(subject=old_subject, episode=old_episode).first()
                if handoff:
                    handoff.progress = new_progress

        # Always sync subject, episode, and chapter in handoff
        handoff = EditorHandoff.query.filter_by(subject=old_subject, episode=old_episode).first()
        if handoff:
            handoff.subject = new_subject
            handoff.episode = new_episode
            handoff.chapter = new_chapter

        db.session.commit()
        return redirect(url_for('review'))

    subjects = [s.name for s in Subject.query.all()]
    return render_template('edit_video.html', video=video, subjects=subjects)


@app.route('/delete_video/<int:video_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)

    handoff = EditorHandoff.query.filter_by(subject=video.subject, episode=video.episode).first()
    if handoff:
        db.session.delete(handoff)

    db.session.delete(video)
    db.session.commit()

    return redirect(url_for('review'))


@app.route('/download_ppt/<path:filename>')
def download_ppt(filename):
    """Serves PowerPoint files from the configured UPLOAD_FOLDER."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


from flask import redirect




from flask import send_file, redirect



from flask import send_file, redirect
import os
import io
import pandas as pd
from datetime import datetime

@app.route('/download_file/<path:filename>')
def download_file(filename):
    try:
        filepath = os.path.join('static', 'documentuploads', filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            return f"❌ File not found: {filename}", 404
    except Exception as e:
        return f"Download failed: {str(e)}", 500




@app.route('/download/<subject>')
def download_subject(subject):
    videos = Video.query.filter_by(subject=subject, status='Approved').all()

    data = []
    for v in videos:
        formatted_date = v.date if isinstance(v.date, str) else v.date.strftime('%Y-%m-%d') if v.date else ''
        data.append({
            'Subject': v.subject,
            'Chapter': v.chapter,
            'Episode': v.episode,
            'Date': formatted_date
        })

    df = pd.DataFrame(data)
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Approved Videos')

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name=f'{subject}_approved.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )





from flask import request, redirect, url_for, render_template, session
from flask_login import logout_user

# ---------------- SUBJECT ROUTES ----------------

@app.route('/subjects', methods=['GET', 'POST'])
def manage_subjects():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if name:
            existing = Subject.query.filter_by(name=name).first()
            if not existing:
                db.session.add(Subject(name=name))
                db.session.commit()

    subjects = Subject.query.all()
    return render_template('subjects.html', subjects=subjects)


# ---------------- USER ROUTES ----------------

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = Users.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        return redirect(url_for('usermanagement'))

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('usermanagement'))


@app.route('/usermanagement')
def usermanagement():
    if not session.get('user_id') or not session.get('is_admin'):
        return redirect(url_for('login'))

    users = Users.query.all()
    return render_template('usermanagement.html', users=users)


# ---------------- SESSION LOGOUT ----------------

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))










import pandas as pd
from datetime import datetime
import os

@app.route('/upload_excel', methods=['POST'])
def upload_excel():
    file = request.files.get('excel_file')
    if not file:
        return "No file uploaded", 400

    try:
        df = pd.read_excel(file)
    except Exception as e:
        return f"Invalid Excel file: {e}", 400

    required_columns = {'Subject', 'Chapter', 'Episode'}
    if not required_columns.issubset(df.columns):
        return "Missing required columns: Subject, Chapter, Episode", 400

    allowed_statuses = {
        "pending": "Pending",
        "under review": "Under Review",
        "approved": "Approved"
    }

    # ✅ Load subjects from DB
    subject_objs = Subject.query.all()
    existing_subjects = {s.name.lower().strip(): s.name for s in subject_objs}

    # ✅ Load existing subject+episode combos
    videos = Video.query.with_entities(Video.subject, Video.episode).all()
    existing_videos = {(v.subject.strip().lower(), v.episode.strip().lower()) for v in videos}

    new_videos = []

    for _, row in df.iterrows():
        subject_input = str(row['Subject']).strip().lower()
        chapter = str(row['Chapter']).strip()
        episode = str(row['Episode']).strip()

        raw_status = str(row['Status']).strip().lower() if 'Status' in df.columns and pd.notna(row['Status']) else "under review"
        status = allowed_statuses.get(raw_status, "Under Review")

        subject = existing_subjects.get(subject_input)
        if not subject:
            print(f"[Skipped] Unknown subject: {row['Subject']}")
            continue

        key = (subject.lower(), episode.lower())
        if key in existing_videos:
            print(f"[Duplicate Denied] Subject: {subject} | Episode: {episode}")
            continue

        new_videos.append(Video(
            subject=subject,
            chapter=chapter,
            episode=episode,
            status=status,
            date=datetime.today().strftime('%Y-%m-%d'),
            file_path=None
        ))
        existing_videos.add(key)

    if new_videos:
        db.session.bulk_save_objects(new_videos)
        db.session.commit()

    return redirect(url_for('review'))







@app.route('/dashboard')
def dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('login'))  # Only admins can access
    return render_template('dashboard.html')


# ── Admin-only Editors overview ───────────────────────────────────────────────











from flask_login import login_required, current_user
from collections import defaultdict
from datetime import datetime


@app.route('/editors')
@login_required
@roles_required('operator_admin', 'manager', 'editor')
def editors():
    # ✅ Log access once per session
    if not session.get('editors_page_logged'):
        log = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Accessed Editors Page",
            status="Success",
            is_admin=True,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
        session['editors_page_logged'] = True

    # 👇 Existing logic
    filter_editor = request.args.get('filter')
    sort_dir = request.args.get('sort')
    subject_filter = request.args.get('subject_filter') # New subject filter parameter

    editors = Editor.query.all()
    all_subjects = [s.name for s in Subject.query.order_by(Subject.name).all()] # Fetch all subjects
    handoffs = EditorHandoff.query.all()

    # Attach profile picture URLs
    for e in editors:
        filename = e.profile_picture or "default.png"
        e.profile_picture_url = url_for("serve_profile_image", filename=filename)

    editor_lookup = {str(e.id): e for e in editors}

    # Optional filter by editor
    if filter_editor:
        handoffs = [h for h in handoffs if str(h.editor_id) == filter_editor]

    # Optional filter by subject (new)
    if subject_filter:
        handoffs = [h for h in handoffs if h.subject == subject_filter]

    # Sort by date by default
    handoffs.sort(key=lambda h: h.date_assigned or '', reverse=True)

    # Optional sort by editor name
    if sort_dir in ("asc", "desc"):
        reverse = (sort_dir == "desc")
        handoffs.sort(
            key=lambda h: editor_lookup.get(str(h.editor_id)).name.lower() if editor_lookup.get(str(h.editor_id)) else '',
            reverse=reverse
        )

    # 🔢 Initialize task counts per editor
    task_counts = defaultdict(lambda: {"Re-editing": 0, "Ongoing": 0, "Finished": 0})

    # 🧾 Count task statuses per editor
    for h in handoffs:
        if h.editor_id:
            progress = h.progress.strip()
            if progress in task_counts[h.editor_id]:
                task_counts[h.editor_id][progress] += 1

    # Attach editor object to each handoff
    for h in handoffs:
        h.editor = editor_lookup.get(str(h.editor_id)) or Editor(name="Unknown", profile_picture="default.png")
        h.editor.profile_picture_url = url_for("serve_profile_image", filename=h.editor.profile_picture or "default.png")

    # Assuming 'handoffs' is a list of objects with a 'subject' attribute
    subjects = sorted({h.subject for h in handoffs if h.subject})
    return render_template(
        "editors.html",
        editors=editors,
        handoffs=handoffs,
        current_filter=filter_editor,
        current_sort=sort_dir,
        all_subjects=all_subjects, # Pass all subjects to the template
        current_subject_filter=subject_filter, # Pass current subject filter to the template
        task_counts=task_counts,
        subjects=subjects,  # <-- add this line
        current_page='editors'
    )





@app.route('/add_handoff', methods=['POST'])
@login_required
@roles_required('operator_admin')
def add_handoff():
    subject = request.form['subject'].strip()
    episode_raw = request.form['episode'].strip()
    episode = normalize_episode(episode_raw) # Normalize the episode
    chapter = request.form.get('chapter', '').strip()
    progress = request.form['progress'].strip()
    editor_id = int(request.form['editor_id'])

    editor = Editor.query.get(editor_id)
    if not editor:
        flash("❌ Invalid editor selected.", "error")
        return redirect(url_for('editors'))

    # Check for existing handoff using python-side normalization
    existing_handoffs = EditorHandoff.query.filter_by(subject=subject).all()
    for h in existing_handoffs:
        if normalize_episode(h.episode) == episode:
            flash(f"⚠️ This handoff for episode '{episode_raw}' already exists.", "error")
            return redirect(url_for('editors'))

    handoff = EditorHandoff(
        subject=subject,
        episode=episode, # Save the normalized episode
        chapter=chapter,
        progress=progress,
        date_assigned=date.today(),
        editor_id=editor_id
    )
    db.session.add(handoff)

    # Create video if progress is 'Finished' and video doesn't exist
    if progress == 'Finished':
        existing_video = Video.query.filter_by(subject=subject, episode=episode).first()
        if not existing_video:
            new_video = Video(
                subject=subject,
                episode=episode,
                chapter=chapter,
                status='Under Review',
                date=date.today(),
                editor_id=editor_id
            )
            db.session.add(new_video)

    db.session.commit()
    flash("✅ New handoff added successfully.", "success")
    return redirect(url_for('editors'))



@app.route('/update_handoff/<int:handoff_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def update_handoff(handoff_id):
    handoff = EditorHandoff.query.get_or_404(handoff_id)

    new_editor_id = int(request.form['editor_id'])
    new_progress = request.form['progress']

    handoff.editor_id = new_editor_id
    handoff.progress = new_progress

    subject = handoff.subject
    episode = handoff.episode
    chapter = handoff.chapter

    # Sync with Video table
    if new_progress == "Ongoing":
        Video.query.filter_by(subject=subject, episode=episode).delete()
    else:
        status_map = {
            "Finished": "Under Review",
            "Re-editing": "Pending",
            "Approved": "Approved"
        }
        desired_status = status_map.get(new_progress, new_progress)

        existing_video = Video.query.filter_by(subject=subject, episode=episode).first()
        if existing_video:
            existing_video.editor_id = new_editor_id
            existing_video.status = desired_status
        else:
            new_video = Video(
                subject=subject,
                episode=episode,
                chapter=chapter,
                status=desired_status,
                date=date.today(),
                editor_id=new_editor_id
            )
            try:
                db.session.add(new_video)
            except IntegrityError:
                db.session.rollback()

    db.session.commit()

    message = "✅ Handoff synced to Review successfully."
    # Always return JSON to avoid unintended flash messages on other pages.
    # The frontend JavaScript will be responsible for showing this message.
    return jsonify(message=message, category="success")







from werkzeug.utils import secure_filename
import os

@app.route('/manage_editors')
def manage_editors():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    editors = Editor.query.all()
    for e in editors:
        e.profile_picture_url = url_for('serve_profile_image', filename=e.profile_picture or "default.png")
    return render_template('manage_editors.html', editors=editors)


@app.route('/editors/upload_pic/<int:editor_id>', methods=['POST'])
def upload_editor_pic(editor_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    editor = Editor.query.get_or_404(editor_id)
    file = request.files.get('profile_pic')

    if not file or not file.filename:
        flash('No file selected', 'error')
        return redirect(url_for('manage_editors'))

    filename = secure_filename(f"{editor.name}_{file.filename}")
    save_path = os.path.join('static', 'profileuploads', filename)
    file.save(save_path)

    editor.profile_picture = filename
    db.session.commit()

    flash(f'✅ Updated picture for {editor.name}', 'success')
    return redirect(url_for('manage_editors'))


@app.route('/add_editor', methods=['POST'])
@login_required
@roles_required('operator_admin')
def add_editor():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    name = request.form['name']
    file = request.files.get('profile_picture')

    filename = None
    if file and file.filename:
        filename = secure_filename(file.filename)
        save_path = os.path.join('static', 'profileuploads', filename)
        file.save(save_path)

    new_editor = Editor(name=name, profile_picture=filename)
    db.session.add(new_editor)
    db.session.commit()

    flash('✅ New editor added.', 'success')
    return redirect(url_for('manage_editors'))




@app.route('/admin/assign_profile_images_by_username')
def assign_profile_images_by_username():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    folder = 'static/profile_pics'
    count = 0

    # Load all editors
    editors = Editor.query.all()
    editor_lookup = {editor.name: editor for editor in editors}

    for filename in os.listdir(folder):
        name, ext = os.path.splitext(filename)
        if ext.lower() not in ['.jpg', '.jpeg', '.png']:
            continue

        editor = editor_lookup.get(name)
        if editor:
            editor.profile_picture = f"profile_pics/{filename}"
            count += 1

    db.session.commit()
    return f"✅ {count} profile pictures assigned successfully by username!"





@app.route('/bulk_upload_handoffs', methods=['POST'])
@login_required
@roles_required('operator_admin')
def bulk_upload_handoffs():
    if 'excel_file' not in request.files:
        flash('❌ No file uploaded.', 'error')
        return redirect(request.referrer)

    file = request.files['excel_file']
    if not file.filename.endswith('.xlsx'):
        flash('❌ Please upload a valid Excel (.xlsx) file.', 'error')
        return redirect(request.referrer)

    try:
        df = pd.read_excel(file, engine='openpyxl')
    except Exception as e:
        flash(f'❌ Error reading Excel file: {str(e)}', 'error')
        return redirect(request.referrer)

    # Ensure required columns exist
    required_columns = {'subject', 'episode', 'progress', 'editor_id'}
    df.columns = [col.lower().strip() for col in df.columns]
    if not required_columns.issubset(df.columns):
        flash('❌ Excel is missing required columns: subject, episode, progress, editor_id.', 'error')
        return redirect(request.referrer)

    created = 0
    skipped = 0

    # Pre-load existing handoffs to avoid repeated DB queries inside the loop
    all_handoffs = EditorHandoff.query.all()
    existing_handoff_keys = {
        (h.subject.strip().lower(), normalize_episode(h.episode)) for h in all_handoffs
    }

    for _, row in df.iterrows():
        subject_raw = str(row['subject']).strip()
        episode_raw = str(row['episode']).strip()
        progress = str(row['progress']).strip()
        editor_id_val = row['editor_id']

        if not subject_raw or not episode_raw or not progress or pd.isna(editor_id_val):
            skipped += 1
            continue
        
        editor_id = int(editor_id_val)
        subject_lower = subject_raw.lower()
        episode = normalize_episode(episode_raw)

        # Check if handoff already exists using the pre-loaded set
        if (subject_lower, episode) in existing_handoff_keys:
            skipped += 1
            continue

        # Create the handoff
        new_handoff = EditorHandoff(
            subject=subject_raw,
            episode=episode, # Save normalized episode
            progress=progress,
            date_assigned=date.today(),
            editor_id=editor_id
        )
        db.session.add(new_handoff)
        existing_handoff_keys.add((subject_lower, episode)) # Add to set to avoid duplicates in same file

        # Optionally add to Review
        if progress in ['Finished', 'Re-editing']:
            # Normalize episode for video check as well
            existing_review_check = Video.query.filter(
                func.lower(Video.subject) == subject_lower,
                func.lower(Video.episode) == episode
            ).first()

            if not existing_review_check:
                status = 'Under Review' if progress == 'Finished' else 'Pending'
                review = Video(
                    subject=subject_raw,
                    episode=episode, # Save normalized episode to Video as well
                    chapter='',
                    status=status,
                    date=date.today(),
                    editor_id=editor_id
                )
                db.session.add(review)

        created += 1

    db.session.commit()

    flash(f'✅ {created} handoffs uploaded successfully. Skipped {skipped} already existing ones.', 'success')
    return redirect(request.referrer)





@app.route('/upload-editor-assignments', methods=['GET', 'POST'])
def upload_editor_assignments():
    if request.method == 'POST':
        file = request.files.get('excel_file')
        if not file or not file.filename.endswith('.xlsx'):
            flash("Upload a valid Excel (.xlsx) file.")
            return redirect(request.url)

        import pandas as pd
        df = pd.read_excel(file)

        def normalize_ep(val):
            return (
                str(val)
                .lower()
                .replace('ep', '')
                .replace('epo_', '')
                .replace('ep_', '')
                .replace(' ', '')
                .lstrip('0')
                .strip()
            )

        updated_count = 0

        # Load all videos and editors once
        all_videos = Video.query.all()
        all_editors = Editor.query.all()

        for _, row in df.iterrows():
            subject = str(row.get('subject', '')).strip().lower()
            raw_episode = str(row.get('episode', '')).strip()
            editor_name = str(row.get('editor_name', '')).strip().lower()

            normalized_ep = normalize_ep(raw_episode)

            # Match editor
            matched_editor = next((e for e in all_editors if e.name.strip().lower() == editor_name), None)
            if not matched_editor:
                print(f"❌ No editor match: {editor_name}")
                continue

            # Match video
            matched_video = None
            for v in all_videos:
                if v.subject.strip().lower() == subject:
                    db_normalized_ep = normalize_ep(v.episode)
                    if db_normalized_ep == normalized_ep:
                        matched_video = v
                        break

            if not matched_video:
                print(f"❌ No video match: {subject} | {raw_episode}")
                continue

            # Update video with editor assignment
            matched_video.editor_id = matched_editor.id
            updated_count += 1

        db.session.commit()

        flash(f"{updated_count} editor assignments successfully updated.")
        return redirect(url_for('upload_editor_assignments'))

    return render_template('upload_editor_page.html')







# this route will help me to sync the reveiw and editors page even for future updates


@app.route('/sync-review-to-editors')
def sync_review_to_editors():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    videos = Video.query.all()
    # Normalize existing handoff keys for a robust check
    existing_handoffs = EditorHandoff.query.all()
    existing_keys = {(h.subject.strip().lower(), normalize_episode(h.episode)) for h in existing_handoffs}

    created = 0
    skipped = 0

    status_to_progress = {
        'Approved': 'Approved',
        'Pending': 'Re-editing',
        'Under Review': 'Finished'
    }

    for video in videos:
        # Normalize the video's episode before checking for existence
        normalized_video_episode = normalize_episode(video.episode)
        key = (video.subject.strip().lower(), normalized_video_episode)
        if key in existing_keys:
            skipped += 1
            continue

        progress = status_to_progress.get(video.status, 'Ongoing')

        new_handoff = EditorHandoff(
            subject=video.subject,
            episode=normalized_video_episode, # Save the normalized episode
            chapter=video.chapter or '',
            progress=progress,
            date_assigned=video.date,
            editor_id=video.editor_id
        )
        db.session.add(new_handoff)
        created += 1

    db.session.commit()
    return f"✅ {created} handoffs created from review, {skipped} already existed."


@app.route('/patch-missing-chapters')
def patch_missing_chapters():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    handoffs = EditorHandoff.query.filter(EditorHandoff.chapter == None).all()
    if not handoffs:
        return "✅ 0 patched — no missing chapters."

    videos = Video.query.filter(Video.chapter != None).all()
    video_lookup = {
        (v.subject.lower(), v.episode): v.chapter for v in videos
    }

    patched = 0
    for h in handoffs:
        key = (h.subject.lower(), h.episode)
        chapter = video_lookup.get(key)
        if chapter:
            h.chapter = chapter
            patched += 1

    db.session.commit()
    return f"✅ {patched} handoff chapters patched from Video table."



def generate_signed_urls(editors_list, supabase_client):
    for editor in editors_list:
        path = editor.get("profile_picture")
        if path:
            try:
                res = supabase_client.storage.from_("profileuploads").create_signed_url(path, 3600)
                editor["signed_url"] = res.get("signedURL")
            except:
                editor["signed_url"] = url_for("static", filename="default.png")
        else:
            editor["signed_url"] = url_for("static", filename="default.png")
    return editors_list









from flask_login import login_required, current_user
from datetime import datetime

@app.route('/dashboard/raw_videos')
@login_required
@roles_required('operator_admin', 'manager')
def dashboard_raw_videos():
    # ✅ Log access once per session
    if not session.get('raw_videos_page_logged'):
        log = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Accessed Raw Videos Page",
            status="Success",
            is_admin=True,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
        session['raw_videos_page_logged'] = True

    # 🧾 Fetch and process data
    raw_videos = RawVideo.query.order_by(RawVideo.date.desc()).all()
    editors = Editor.query.all()
    all_subjects = Subject.query.order_by(Subject.name).all() # For the "Add" dropdown

    subjects = db.session.query(RawVideo.subject).distinct().all()
    subjects = [s[0] for s in subjects if s[0]]

    # Profile picture lookup
    editor_lookup = {
        e.id: {
            "name": e.name,
            "profile_picture": url_for("serve_profile_image", filename=e.profile_picture or "default.png")
        } for e in editors
    }

    enriched_raw_videos = []
    for r in raw_videos:
        editor_info = editor_lookup.get(r.editor_id)
        if editor_info:
            editor_info['signed_url'] = url_for("serve_profile_image", filename=Editor.query.get(r.editor_id).profile_picture or "default.png")

        enriched_raw_videos.append({
            "id": r.id,
            "subject": r.subject,
            "episode": r.episode,
            "chapter": r.chapter,
            "editor_id": r.editor_id,
            "status": r.status,
            "date": r.date,
            "editor": editor_info
        })

    enriched_editors = []
    for e in editors:
        enriched_editors.append({
            "id": e.id,
            "name": e.name,
            "profile_picture": e.profile_picture,
            "signed_url": url_for("serve_profile_image", filename=e.profile_picture or "default.png")
        })



        

    return render_template(
        "dashboard_raw_videos.html",
        raw_videos=enriched_raw_videos,
        editors=enriched_editors,
        subjects=subjects,
        all_subjects=all_subjects,
        current_page='dashboard_raw_videos'
    )



@app.route('/edit_raw_video/<int:raw_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def edit_raw_video(raw_id):
    try:
        raw_video = RawVideo.query.get(raw_id)
        if not raw_video:
            return jsonify({"success": False, "error": "Raw video not found"}), 404

        # Save original subject and episode before editing
        original_subject = raw_video.subject
        original_episode = raw_video.episode

        # Get new values from the form
        subject = request.form['subject']
        episode = request.form['episode']
        chapter = request.form['chapter']
        date = request.form['date']

        # Update the raw video
        raw_video.subject = subject
        raw_video.episode = episode
        raw_video.chapter = chapter
        raw_video.date = date

        # Update the corresponding EditorHandoff record
        handoff = EditorHandoff.query.filter_by(subject=original_subject, episode=original_episode).first()
        if handoff:
            handoff.subject = subject
            handoff.episode = episode
            handoff.chapter = chapter

        # Update the corresponding Video record
        video = Video.query.filter_by(subject=original_subject, episode=original_episode).first()
        if video:
            video.subject = subject
            video.episode = episode
            video.chapter = chapter

        db.session.commit()
        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
        print(f"Error updating raw video: {e}")
        return jsonify({"success": False, "error": str(e)}), 500






@app.route('/add_raw_video', methods=['POST'])
@login_required
@roles_required('operator_admin')
def add_raw_video():
    subject = request.form['subject'].strip()
    episode = request.form['episode'].strip()
    normalized_episode = normalize_episode(episode)
    chapter = request.form['chapter'].strip()
    date_value = request.form['date']

    if not normalized_episode:
        flash("⚠️ Episode could not be normalized. Please provide a valid episode (e.g., 'Ep 1', 'Episode 01').", 'danger')
        return redirect(url_for('dashboard_raw_videos'))

    # 🔍 Check for existing raw videos for this subject by iterating
    # This is necessary because episodes already in the DB might not be normalized yet.
    existing_raws = RawVideo.query.filter(func.lower(RawVideo.subject) == subject.lower()).all()
    for raw in existing_raws:
        if normalize_episode(raw.episode) == normalized_episode:
            flash(f"Duplicate Found: '{subject.title()} - Ep {episode}' was not added.", 'warning')
            return redirect(url_for('dashboard_raw_videos'))

    # ✅ Add new raw video
    new_raw = RawVideo(
        subject=subject.title(),
        episode=normalized_episode, # Save the normalized episode for consistency
        chapter=chapter,
        date=date_value,
        status="Not Assigned"
    )
    db.session.add(new_raw)
    db.session.commit()

    flash("✅ 1 new raw video added successfully!", "success")
    return redirect(url_for('dashboard_raw_videos'))








@app.route('/assign_editor_to_raw/<int:raw_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def assign_editor_to_raw(raw_id):
    editor_id = int(request.form.get('editor_id'))

    # Fetch raw video
    raw_video = RawVideo.query.get(raw_id)
    if not raw_video:
        return jsonify({'success': False, 'error': 'Raw video not found'}), 404

    # Fetch editor
    editor = Editor.query.get(editor_id)
    if not editor:
        return jsonify({'success': False, 'error': 'Editor not found'}), 404

    # Update raw video assignment
    raw_video.editor_id = editor_id
    raw_video.status = "Assigned"

    # Create or update handoff
    handoff = EditorHandoff.query.filter_by(
        subject=raw_video.subject,
        episode=raw_video.episode
    ).first()

    if handoff:
        handoff.editor_id = editor_id
    else:
        new_handoff = EditorHandoff(
            subject=raw_video.subject,
            episode=raw_video.episode,
            chapter=raw_video.chapter or "",
            progress="Ongoing",
            date_assigned=date.today(),
            editor_id=editor_id
        )
        db.session.add(new_handoff)

    db.session.commit()

    profile_url = url_for("serve_profile_image", filename=editor.profile_picture or "default.png")

    return jsonify({
        'success': True,
        'editor_name': editor.name,
        'profile_picture': editor.profile_picture,
        'signed_url': profile_url
    })


@app.route('/unassign_editor_from_raw/<int:raw_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def unassign_editor_from_raw(raw_id):
    raw_video = RawVideo.query.get(raw_id)
    if not raw_video:
        return jsonify({'success': False, 'error': 'Raw video not found'}), 404

    # Get the editor before unassigning
    editor = raw_video.editor

    # Delete handoff if exists
    handoff = EditorHandoff.query.filter_by(
        subject=raw_video.subject,
        episode=raw_video.episode
    ).first()

    if handoff:
        db.session.delete(handoff)

    # Reset raw video assignment
    raw_video.editor_id = None
    raw_video.status = "Not Assigned"

    db.session.commit()

    return jsonify({
        'success': True
    })







@app.route('/bulk_upload_raw_videos', methods=['POST'])
@login_required
@roles_required('operator_admin')
def bulk_upload_raw_videos():
    file = request.files.get('excel_file')

    if not file:
        flash("No file uploaded.", "error")
        return redirect(url_for('dashboard_raw_videos'))

    try:
        df = pd.read_excel(file)
    except Exception as e:
        flash(f"Error reading Excel file: {e}", "error")
        return redirect(url_for('dashboard_raw_videos'))

    created = 0
    skipped = 0
    new_videos = []

    # Pre-load existing raw videos for efficient duplicate checking
    all_raws = RawVideo.query.all()
    existing_raw_keys = {
        (r.subject.strip().lower(), normalize_episode(r.episode)) for r in all_raws
    }

    for _, row in df.iterrows():
        subject_raw = str(row.get('Subject', '')).strip()
        episode_raw = str(row.get('Episode', '')).strip()
        chapter = str(row.get('Chapter', '')).strip()
        date_value = row.get('Date')

        if not subject_raw or not episode_raw:
            skipped += 1
            continue

        # 🛡️ Use today's date if blank
        if pd.isna(date_value) or not str(date_value).strip():
            date_value = date.today()
        else:
            date_value = pd.to_datetime(date_value).date()

        normalized_ep = normalize_episode(episode_raw)
        subject_lower = subject_raw.lower()

        # 🔍 Check for duplicates using the pre-loaded set
        if (subject_lower, normalized_ep) in existing_raw_keys:
            skipped += 1
            continue

        new_raw = RawVideo(
            subject=subject_raw.title(), # Keep consistent title casing
            episode=normalized_ep,       # Save the normalized episode
            chapter=chapter,
            date=date_value,
            status="Not Assigned"
        )
        new_videos.append(new_raw)
        existing_raw_keys.add((subject_lower, normalized_ep)) # Add to set to avoid dups in same file
        created += 1

    if new_videos:
        db.session.bulk_save_objects(new_videos)
        db.session.commit()

    flash(f"✅ Bulk upload complete: {created} raw videos uploaded. Skipped {skipped} duplicate(s) or row(s) with missing data.", "success")
    return redirect(url_for('dashboard_raw_videos'))





@app.route('/bulk_assign_editor', methods=['POST'])
@login_required
@roles_required('operator_admin')
def bulk_assign_editor():
    editor_id = request.form.get('editor_id')
    raw_ids = request.form.get('raw_ids')

    if not editor_id or not raw_ids:
        return jsonify({"success": False, "error": "Missing data"})

    try:
        raw_ids = json.loads(raw_ids)
        editor_id = int(editor_id)
    except Exception as e:
        return jsonify({"success": False, "error": "Invalid data: " + str(e)})

    updated = 0

    for raw_id in raw_ids:
        raw = RawVideo.query.get(raw_id)
        if not raw:
            continue

        # Assign editor to raw video
        raw.editor_id = editor_id
        raw.status = "Assigned"

        # Create or update editor handoff
        handoff = EditorHandoff.query.filter_by(
            subject=raw.subject,
            episode=raw.episode
        ).first()

        if handoff:
            handoff.editor_id = editor_id
        else:
            new_handoff = EditorHandoff(
                subject=raw.subject,
                episode=raw.episode,
                chapter=raw.chapter or "",
                date_assigned=date.today(),
                progress="Ongoing",
                editor_id=editor_id
            )
            db.session.add(new_handoff)

        updated += 1

    db.session.commit()

    editor = Editor.query.get(editor_id)
    editor_data = {
        'id': editor.id,
        'name': editor.name,
        'signed_url': url_for("serve_profile_image", filename=editor.profile_picture or "default.png")
    }

    return jsonify({"success": True, "updated": updated, "editor_data": editor_data})







from flask import Blueprint, request, send_file, abort
from io import BytesIO
import pandas as pd

@app.route('/download_editor_tasks/<int:editor_id>')
def download_editor_tasks(editor_id):
    status = request.args.get('status')

    if not status:
        return abort(400, description="Missing status parameter")

    # Query matching handoffs
    handoffs = EditorHandoff.query.filter_by(editor_id=editor_id, progress=status).all()

    if not handoffs:
        return abort(404, description="No handoffs found")

    # Convert to DataFrame
    data = [{
        "Subject": h.subject,
        "Episode": h.episode,
        "Chapter": h.chapter,
        "Editor": h.editor.name if h.editor else "Unknown",
        "Status": h.progress,
    
    "Assigned": (
        h.date_assigned.strftime("%Y-%m-%d")
        if isinstance(h.date_assigned, datetime)
        else h.date_assigned or ""
    )
} for h in handoffs]
    

    df = pd.DataFrame(data)

    # Export to Excel in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Tasks')
    output.seek(0)

    filename = f"editor_{editor_id}_{status.replace(' ', '_')}.xlsx"
    return send_file(output,
                     download_name=filename,
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')





@app.route('/download_all_subjects')
def download_all_subjects():
    from io import BytesIO
    import pandas as pd
    from openpyxl import Workbook
    from openpyxl.utils.dataframe import dataframe_to_rows

    output = BytesIO()
    wb = Workbook()
    wb.remove(wb.active)

    subjects = db.session.query(Subject.name).all()
    subjects = [s[0] for s in subjects]

    for subject in subjects:
        videos = Video.query.filter_by(subject=subject, status='Approved').all()
        if not videos:
            continue

        data = []
        for v in videos:
            data.append({
                'Subject': v.subject,
                'Chapter': v.chapter,
                'Episode': v.episode,
                'Date': v.date.strftime('%Y-%m-%d') if hasattr(v.date, 'strftime') else v.date
            })

        df = pd.DataFrame(data)
        sheet = wb.create_sheet(title=subject[:31])
        for row in dataframe_to_rows(df, index=False, header=True):
            sheet.append(row)

    # Modern approach: save directly to BytesIO buffer
    wb.save(output)
    output.seek(0)

    return send_file(output,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True,
                     download_name='All_Approved_Videos.xlsx')




from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from flask_login import LoginManager





login_manager = LoginManager()
login_manager.login_view = 'login'  # name of your login route
login_manager.init_app(app)         # ✅ This is required


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.context_processor
def inject_notifications():
    """
    Injects unread notification count and details into all templates
    for the logged-in user.
    """
    if not current_user.is_authenticated:
        return dict(
            unread_notifications_count=0, 
            notifications=[], 
            toast_notifications=[],
            admin_toasts=[],
            editor_toasts=[],
            new_comment_notifications_count=0,
            new_submission_notifications_count=0
        )

    # --- Standard Notifications for Bell Icon ---
    unread_notifications = Notification.query.options(
        joinedload(Notification.comment)
    ).filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    
    # --- Session-Based Toast Notifications ---
    if 'shown_toast_ids' not in session:
        session['shown_toast_ids'] = []

    toast_notifications = [
        n for n in unread_notifications 
        if n.id not in session['shown_toast_ids']
    ]
    
    # --- Add custom headers to toast notifications for the template ---
    for n in toast_notifications:
        if n.notification_type == 'comment':
            n.header = "New Feedback Received"
        elif n.notification_type == 'submission':
            n.header = "New Submission from Editor"
        elif n.notification_type == 'password_reset':
            n.header = "Security Alert"
        elif n.notification_type == 'schedule_reminder':
            n.header = "Schedule Reminder"
        else:
            n.header = "Notification" # Default header

    # Add the new toast IDs to the session so they don't show again
    for n in toast_notifications:
        session['shown_toast_ids'].append(n.id)
    session.modified = True # Ensure the session is saved

    # --- Create separate lists for different toast designs ---
    admin_toast_types = ['submission', 'password_reset', 'schedule_reminder']
    admin_toasts = [n for n in toast_notifications if n.notification_type in admin_toast_types]
    editor_toasts = [n for n in toast_notifications if n.notification_type == 'comment']

    # --- Sidebar Badges for specific notification types (unread) ---
    new_comment_notifications_count = Notification.query.filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
        Notification.notification_type == 'comment'
    ).count()

    new_submission_notifications_count = Notification.query.filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
        Notification.notification_type == 'submission'
    ).count()

    return dict(
        unread_notifications_count=len(unread_notifications),
        notifications=unread_notifications,
        toast_notifications=toast_notifications, # Kept for compatibility
        admin_toasts=admin_toasts,               # New list for admin-specific toasts
        editor_toasts=editor_toasts,             # New list for editor-specific toasts
        new_comment_notifications_count=new_comment_notifications_count,
        new_submission_notifications_count=new_submission_notifications_count
    )







from datetime import datetime


@app.route('/user_management', methods=['GET', 'POST'])
def manage_users():
    if not current_user.is_authenticated:
        return render_template("not_authorized.html", message="Please log in to access this page.")

    if not current_user.is_admin:
        # Log denied access attempt
        log = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Tried to access user management",
            status="Denied",
            is_admin=False,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
        return render_template("not_authorized.html", message="Only admins can access this page.")

    # ✅ Admin verified — log successful access
    log = ActivityLog(
        user_id=current_user.id,
        username=current_user.username,
        action="Accessed user management",
        status="Success",
        is_admin=True,
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(log)
    db.session.commit()

    # Fetch users and logs
    users = Users.query.all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()  # Show recent logs

    return render_template("user_management.html", users=users, logs=logs)








@app.route('/source', methods=['GET', 'POST'])
@login_required
def source_page():
    # ✅ Admin-only access
    if not current_user.is_admin:
        log = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Tried to access Source Page",
            status="Denied",
            is_admin=False,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
        return render_template("not_authorized.html", message="Only admins can access the Source page.")

    # ✅ Log successful access once per session
    if not session.get('source_page_logged'):
        log = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Accessed Source Page",
            status="Success",
            is_admin=True,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
        session['source_page_logged'] = True

    # ✅ Handle upload
    if request.method == 'POST':
        subject = request.form['subject'].strip()
        chapter = request.form['chapter'].strip()
        episode = request.form['episode'].strip()
        supervisor_id = request.form.get('supervisor_id')
        ppt_file = request.files.get('ppt_file')

        filename = None
        if ppt_file:
            filename = secure_filename(ppt_file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            ppt_file.save(save_path)

        # Add to DB
        new_source = SourceMaterial(
            subject=subject,
            chapter=chapter,
            episode=episode,
            supervisor_id=supervisor_id,
            ppt_filename=filename
        )
        db.session.add(new_source)
        db.session.commit()
        flash(" Source uploaded successfully.", "success")
        return redirect(url_for('source_page'))

    # ✅ Fetch existing source materials and supervisors
    sources = SourceMaterial.query.order_by(SourceMaterial.id.desc()).all()
    supervisors = Supervisor.query.all()

    return render_template(
        "source_page.html",
        sources=sources,
        supervisors=supervisors,
        current_page='source'
    )




from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

class AdminModelView(ModelView):
    def is_accessible(self):
        # For quick test: return True (so you see menu even if not logged in)
        return True

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin = Admin(app, name='AdminPanel', template_mode='bootstrap4')

admin.add_view(AdminModelView(Users, db.session))
admin.add_view(AdminModelView(Editor, db.session))
admin.add_view(AdminModelView(Subject, db.session))
admin.add_view(AdminModelView(Supervisor, db.session))
admin.add_view(AdminModelView(SourceMaterial, db.session))



from datetime import datetime

@app.route('/quick_review')
@login_required
@roles_required('operator_admin', 'manager', 'supervisor')
def quick_review():
    # Get all sessions and under-review videos
    sessions = QuickReviewSession.query.order_by(QuickReviewSession.created_at.desc()).all()
    videos = Video.query.filter_by(status="Under Review").all()

    # Safely convert items to dicts, sorting them by episode
    session_json = {}
    for session in sessions:
        # Sort items by episode using the helper function
        sorted_items = sorted(session.items, key=lambda item: episode_sort_key(item.episode))
        
        session_json[session.name] = []
        for item in sorted_items:
            session_json[session.name].append({
                'id': item.id,
                'subject': item.subject,
                'episode': item.episode,
                'is_reviewed': item.is_reviewed,
                'comment_file_name': item.comment_file_name
            })

    return render_template(
        "quick_review.html",
        sessions=sessions,
        under_review_videos=videos,
        session_json=session_json,  # ✅ Now safe to use with `| tojson`
        current_page='quick_review'
    )




@app.route('/create_quick_review', methods=['POST'])
@login_required
@roles_required('operator_admin')
def create_quick_review():
    session_name = request.form['session_name']
    selected = request.form.getlist('selected_videos')  # Format: subject||episode

    session = QuickReviewSession(name=session_name)
    db.session.add(session)
    db.session.flush()

    for entry in selected:
        subject, episode = entry.split('||')
        db.session.add(QuickReviewItem(session_id=session.id, subject=subject, episode=episode))

    db.session.commit()
    flash('Quick review session created.', 'success')
    return redirect(url_for('quick_review', ))


@app.route('/comments_page')
def comments_page():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 8, type=int)
    if per_page not in [8, 16, 64]:
        per_page = 8
        
    query = ReviewCommentLog.query.order_by(ReviewCommentLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    comments = pagination.items
    for comment in comments:
        comment.filename = os.path.basename(comment.docx_file_path)
        
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    
    return render_template(
        "comments_page.html",
        comments=comments,
        pagination=pagination,
        thirty_days_ago=thirty_days_ago,
        current_page='comments'
    )



@app.route('/progress_tracker')
@login_required
@roles_required('operator_admin', 'manager', 'editor')
def progress_tracker():
    # Get all unique subject names from all relevant tables
    subjects_from_table = {s[0] for s in db.session.query(Subject.name).distinct()}
    subjects_from_videos = {v[0] for v in db.session.query(Video.subject).distinct()}
    subjects_from_raw = {r[0] for r in db.session.query(RawVideo.subject).distinct()}
    subjects_from_handoffs = {h[0] for h in db.session.query(EditorHandoff.subject).distinct()}

    all_subject_names = sorted(list(
        subjects_from_table | subjects_from_videos | subjects_from_raw | subjects_from_handoffs
    ))

    progress_data = []

    # Initialize overall totals
    overall_total_episodes = 0
    overall_total_approved = 0

    for subject_name in all_subject_names:
        if subject_name == 'Chemistry':
            total_episodes = 26
        elif subject_name in ['Math', 'English']:
            total_episodes = 30
        elif subject_name == 'Geography':
            total_episodes = 21
        else:
            total_episodes = 25

        # Fetch all unique editor IDs associated with the subject
        editor_ids = set()
        video_editors = db.session.query(Video.editor_id).filter(Video.subject == subject_name, Video.editor_id.isnot(None)).distinct().all()
        editor_ids.update([e[0] for e in video_editors])
        raw_video_editors = db.session.query(RawVideo.editor_id).filter(RawVideo.subject == subject_name, RawVideo.editor_id.isnot(None)).distinct().all()
        editor_ids.update([e[0] for e in raw_video_editors])
        handoff_editors = db.session.query(EditorHandoff.editor_id).filter(EditorHandoff.subject == subject_name, EditorHandoff.editor_id.isnot(None)).distinct().all()
        editor_ids.update([e[0] for e in handoff_editors])

        editors_data = []
        if editor_ids:
            editors = Editor.query.filter(Editor.id.in_(list(editor_ids))).all()
            for editor in editors:
                pic_path = 'default.png'
                if editor.profile_picture:
                    # Check if the path is already structured (e.g., "profile_pics/image.png")
                    if '/' in editor.profile_picture or '\\' in editor.profile_picture:
                        pic_path = editor.profile_picture
                    else:
                        # Assume it's in a default folder if it's just a filename
                        pic_path = f"profile_pics/{editor.profile_picture}"
                editors_data.append({
                    'id': editor.id,
                    'name': editor.name, 
                    'pic': pic_path
                })

        # Get counts for each status
        video_counts = db.session.query(
            func.count(case((Video.status == 'Approved', Video.id))).label('approved'),
            func.count(case((Video.status == 'Under Review', Video.id))).label('reviewing'),
            func.count(case((Video.status == 'Pending', Video.id))).label('pending')
        ).filter(Video.subject == subject_name).one()

        ongoing_count = db.session.query(func.count(EditorHandoff.id)).filter(
            EditorHandoff.subject == subject_name,
            EditorHandoff.progress == 'Ongoing'
        ).scalar()

        raw_video_count = db.session.query(func.count(RawVideo.id)).filter(
            RawVideo.subject == subject_name,
            RawVideo.status == 'Not Assigned'
        ).scalar()

        # Calculate totals
        approved_count = video_counts.approved
        reviewing_count = video_counts.reviewing
        pending_count = video_counts.pending
        
        # Corrected 'Remaining' calculation
        remaining = reviewing_count + pending_count + ongoing_count + raw_video_count
        progress_percentage = (approved_count / total_episodes) * 100 if total_episodes > 0 else 0

        # Accumulate for overall tracker
        overall_total_episodes += total_episodes
        overall_total_approved += approved_count

        color_class = 'red'
        if progress_percentage > 80:
            color_class = 'green'
        elif progress_percentage >= 50:
            color_class = 'yellow'

        progress_data.append({
            'subject': subject_name,
            'total_episodes': total_episodes,
            'approved': approved_count,
            'reviewing': reviewing_count,
            'pending': pending_count,
            'ongoing': ongoing_count,
            'raw_videos': raw_video_count,
            'remaining': remaining,
            'progress': round(progress_percentage, 1),
            'color_class': color_class,
            'editors': editors_data
        })

    sorted_progress_data = sorted(progress_data, key=lambda x: x['progress'], reverse=True)

    # Calculate overall progress percentage
    overall_progress_percentage = (overall_total_approved / overall_total_episodes) * 100 if overall_total_episodes > 0 else 0

    # Determine overall color class
    overall_color_class = 'red'
    if overall_progress_percentage > 80:
        overall_color_class = 'green'
    elif overall_progress_percentage >= 50:
        overall_color_class = 'yellow'

    return render_template('progress_tracker.html',
                           progress_data=sorted_progress_data,
                           overall_total_episodes=overall_total_episodes,
                           overall_total_approved=overall_total_approved,
                           overall_progress_percentage=round(overall_progress_percentage, 1),
                           overall_color_class=overall_color_class,
                           current_page='progress_tracker')


@app.route('/api/subject_details')
@login_required
def subject_details():
    subject_name = request.args.get('subject')
    status = request.args.get('status')

    if not subject_name or not status:
        return jsonify({"error": "Missing subject or status"}), 400

    headers = []
    keys = []
    results = []

    if status in ['approved', 'reviewing', 'pending']:
        db_status_map = {'approved': 'Approved', 'reviewing': 'Under Review', 'pending': 'Pending'}
        db_status = db_status_map.get(status)
        
        videos_query = Video.query.options(joinedload(Video.editor)).filter(
            Video.subject == subject_name, Video.status == db_status
        )

        videos = videos_query.order_by(Video.episode).all()
        
        headers = ["Episode", "Chapter", "Editor", "Date"]
        keys = ["episode", "chapter", "editor", "date"]
        
        # Create a lookup for handoff chapters using normalized episode keys
        handoffs = EditorHandoff.query.filter(EditorHandoff.subject == subject_name).all()
        handoff_chapters = {normalize_episode(h.episode): h.chapter for h in handoffs if h.chapter}

        for v in videos:
            # Normalize the video's episode for the lookup
            normalized_video_episode = normalize_episode(v.episode)
            chapter = handoff_chapters.get(normalized_video_episode, v.chapter)

            editor_info = {"name": "Unassigned", "pic": "default.png"}
            if v.editor:
                pic_path = 'default.png'
                if v.editor.profile_picture:
                    if '/' in v.editor.profile_picture or '\\' in v.editor.profile_picture:
                        pic_path = v.editor.profile_picture
                    else:
                        pic_path = f"profile_pics/{v.editor.profile_picture}"
                editor_info = {"name": v.editor.name, "pic": pic_path}
            results.append({"episode": v.episode, "chapter": chapter, "date": v.date, "editor": editor_info})
            
    elif status == 'ongoing':
        handoffs = EditorHandoff.query.options(joinedload(EditorHandoff.editor)).filter(
            EditorHandoff.subject == subject_name, EditorHandoff.progress == 'Ongoing'
        ).order_by(EditorHandoff.episode).all()
        headers = ["Episode", "Chapter", "Editor", "Date Assigned"]
        keys = ["episode", "chapter", "editor", "date"]
        for h in handoffs:
            editor_info = {"name": "Unassigned", "pic": "default.png"}
            if h.editor:
                pic_path = 'default.png'
                if h.editor.profile_picture:
                    if '/' in h.editor.profile_picture or '\\' in h.editor.profile_picture:
                        pic_path = h.editor.profile_picture
                    else:
                        pic_path = f"profile_pics/{h.editor.profile_picture}"
                editor_info = {"name": h.editor.name, "pic": pic_path}
            results.append({"episode": h.episode, "chapter": h.chapter, "date": h.date_assigned, "editor": editor_info})

    elif status == 'raw_videos':
        raw_videos = RawVideo.query.filter_by(subject=subject_name, status='Not Assigned').order_by(RawVideo.episode).all()
        headers = ["Episode", "Chapter", "Date"]
        keys = ["episode", "chapter", "date"]
        results = [{"episode": v.episode, "chapter": v.chapter, "date": v.date} for v in raw_videos]

    elif status == 'remaining':
        headers = ["Episode", "Current Status", "Editor"]
        keys = ["episode", "status", "editor"]
        
        videos_in_progress = Video.query.options(joinedload(Video.editor)).filter(
            Video.subject == subject_name, Video.status.in_(['Under Review', 'Pending'])
        ).all()
        for v in videos_in_progress:
            editor_info = {"name": "Unassigned", "pic": "default.png"}
            if v.editor:
                pic_path = 'default.png'
                if v.editor.profile_picture:
                    if '/' in v.editor.profile_picture or '\\' in v.editor.profile_picture:
                        pic_path = v.editor.profile_picture
                    else:
                        pic_path = f"profile_pics/{v.editor.profile_picture}"
                editor_info = {"name": v.editor.name, "pic": pic_path}
            results.append({"episode": v.episode, "status": v.status, "editor": editor_info})

        handoffs_in_progress = EditorHandoff.query.options(joinedload(EditorHandoff.editor)).filter(
            EditorHandoff.subject == subject_name, EditorHandoff.progress == 'Ongoing'
        ).all()
        for h in handoffs_in_progress:
            editor_info = {"name": "Unassigned", "pic": "default.png"}
            if h.editor:
                pic_path = 'default.png'
                if h.editor.profile_picture:
                    if '/' in h.editor.profile_picture or '\\' in h.editor.profile_picture:
                        pic_path = h.editor.profile_picture
                    else:
                        pic_path = f"profile_pics/{h.editor.profile_picture}"
                editor_info = {"name": h.editor.name, "pic": pic_path}
            results.append({"episode": h.episode, "status": "New-edit", "editor": editor_info})

        unassigned_raw_videos = RawVideo.query.filter(
            RawVideo.subject == subject_name, RawVideo.status == 'Not Assigned'
        ).all()
        for r in unassigned_raw_videos:
            editor_info = {"name": "Unassigned", "pic": "default.png"}
            results.append({"episode": r.episode, "status": "Unassigned (Raw)", "editor": editor_info})
        
    return jsonify({"headers": headers, "keys": keys, "results": results})


@app.route('/mark_reviewed', methods=['POST'])
@login_required
@roles_required('operator_admin', 'supervisor')
def mark_reviewed():
    data = request.get_json()
    item_id = data.get('item_id')
    reviewed = data.get('reviewed')

    item = db.session.get(QuickReviewItem, item_id)
    if not item:
        return jsonify(success=False), 404

    item.is_reviewed = reviewed

    # Find and update the video
    video = Video.query.filter_by(subject=item.subject, episode=item.episode).first()
    if video:
        if reviewed:
            video.status = "Pending"
        else:
            video.status = "Under Review"

    # Find and update the editor handoff (progress field)
    handoff = EditorHandoff.query.filter_by(subject=item.subject, episode=item.episode).first()
    if handoff:
        if reviewed:
            handoff.progress = "Re-editing"
        else:
            handoff.progress = "Finished"

    db.session.commit()
    return jsonify(success=True)




@app.route('/upload_comment', methods=['POST'])
@login_required
@roles_required('operator_admin', 'supervisor')
def upload_comment():
    subject = request.form['subject'].strip()
    episode_raw = request.form['episode'].strip()
    item_id = request.form.get('item_id')
    file = request.files.get('comment_file')

    if not file or not file.filename:
        return jsonify(success=False, error="No file was selected for upload."), 400
        
    normalized_episode = normalize_episode(episode_raw)
    if not normalized_episode:
        return jsonify(success=False, error=f"Invalid episode format: '{episode_raw}'."), 400

    comments_dir = os.path.join(app.root_path, app.config['COMMENT_UPLOAD_FOLDER'])
    os.makedirs(comments_dir, exist_ok=True)
    
    base_pattern = f"{subject}-{normalized_episode}-comment-"
    ext = os.path.splitext(file.filename)[1] or '.docx'

    # Using a retry loop to handle rare race conditions under high load
    for attempt in range(5):
        try:
            # 1. Find the highest existing version number from the DB for this specific episode
            existing_logs = ReviewCommentLog.query.filter(
                ReviewCommentLog.subject == subject,
                ReviewCommentLog.episode == normalized_episode,
                # Look for both hyphen and underscore patterns to be safe
                or_(
                    ReviewCommentLog.docx_file_path.like(f"{subject}-{normalized_episode}-comment-%"),
                    ReviewCommentLog.docx_file_path.like(f"{subject}-{normalized_episode}-comment_%")
                )
            ).with_entities(ReviewCommentLog.docx_file_path).all()

            max_num = 0
            if existing_logs:
                # Extract numbers from filenames like 'Subject-Ep1-comment-3.docx' or 'Subject-Ep1-comment_3.docx'
                nums = [int(re.search(r'[-_](\d+)\.', f[0]).group(1)) for f in existing_logs if re.search(r'[-_](\d+)\.', f[0])]
                if nums:
                    max_num = max(nums)
            
            next_num = max_num + 1
            filename = f"{base_pattern}{next_num}{ext}"
            
            # 2. Save the physical file to disk
            save_path = os.path.join(comments_dir, filename)
            file.stream.seek(0)
            file.save(save_path)

            # 3. Create the database record
            new_log = ReviewCommentLog(
                subject=subject,
                episode=normalized_episode,
                timestamp=datetime.now(timezone.utc),
                docx_file_path=filename
            )
            db.session.add(new_log)
            db.session.flush()

            # 4. Update the quick review item if it exists
            if item_id:
                item = db.session.get(QuickReviewItem, item_id)
                if item:
                    item.comment_file_name = filename
            
            # 5. Create notification for the editor
            handoff = EditorHandoff.query.filter(
                func.lower(EditorHandoff.subject) == subject.lower(),
                EditorHandoff.episode == normalized_episode
            ).first()

            if handoff and handoff.editor:
                editor_user = Users.query.filter(func.lower(Users.username) == handoff.editor.name.lower()).first()
                if editor_user:
                    notification = Notification(
                        user_id=editor_user.id, 
                        comment_id=new_log.id, 
                        is_read=False,
                        message=f"New comment for {subject} - Ep {normalized_episode}",
                        notification_type='comment'
                    )
                    db.session.add(notification)
            
            # 6. Commit the transaction
            db.session.commit()
            
            return jsonify(success=True, message=f"Comment uploaded successfully as Version {next_num}.", filename=filename)

        except IntegrityError:
            # This happens if another request created the same filename between our check and our commit.
            # We roll back, wait a moment, and let the loop retry.
            db.session.rollback()
            time.sleep(0.05) # Small delay to prevent hammering
        
        except Exception as e:
            # For any other error, rollback and report it.
            db.session.rollback()
            print(f"Error during comment upload on attempt {attempt+1}: {e}")
            return jsonify(success=False, error=f"An unexpected server error occurred: {str(e)}"), 500
    
    # If the loop completes without success, it means we failed all retries.
    return jsonify(success=False, error="Could not upload comment due to a server conflict. Please try again."), 500


@app.route('/clear_all_quick_review_sessions', methods=['POST'])
@login_required
@roles_required('operator_admin')
def clear_all_quick_review_sessions():
    """
    Deletes all QuickReviewSession records.
    The database schema's cascade settings will also delete associated
    QuickReviewItems, but this does NOT affect ReviewCommentLog entries
    or physical files.
    """
    try:
        sessions_to_delete = QuickReviewSession.query.all()
        num_deleted = len(sessions_to_delete)
        
        if not sessions_to_delete:
            flash("No sessions to clear.", "info")
            return jsonify(success=True, message="No sessions to clear.")

        for session in sessions_to_delete:
            # This triggers the 'delete-orphan' cascade for QuickReviewItems
            db.session.delete(session)
        
        db.session.commit()
        
        flash(f"{num_deleted} quick review session(s) have been cleared.", "success")
        return jsonify(success=True, message=f"{num_deleted} sessions cleared.")

    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while clearing sessions: {str(e)}"
        print(f"Error in clear_all_quick_review_sessions: {e}") # Log the full error to the console
        flash(error_message, "danger")
        return jsonify(success=False, error=error_message), 500


@app.route('/download_comment/<int:comment_id>')
def download_comment(comment_id):
    comment = ReviewCommentLog.query.get_or_404(comment_id)
    filename = comment.docx_file_path
    if not filename:
        flash("No file is associated with this comment record.", "danger")
        return redirect(request.referrer or url_for('comments_page'))

    # Construct a robust, absolute path to the file
    file_path = os.path.join(app.root_path, app.config['COMMENT_UPLOAD_FOLDER'], filename)

    if not os.path.exists(file_path):
        flash(f"Error: The file '{filename}' could not be found on the server.", "danger")
        return redirect(request.referrer or url_for('comments_page'))
    
    try:
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        flash(f"An error occurred while downloading the file: {e}", "danger")
        return redirect(request.referrer or url_for('comments_page'))


@app.route('/video/<int:video_id>/review', methods=['GET'])
@login_required
def video_review(video_id):
    video = Video.query.get_or_404(video_id)
    return render_template('video_review.html', video=video)

@app.route('/video/<int:video_id>/add_comment', methods=['POST'])
@login_required
def add_timestamp_comment(video_id):
    video = Video.query.get_or_404(video_id)
    minutes = request.form.get('minutes')
    seconds = request.form.get('seconds')
    comment_text = request.form.get('comment')
    photo = request.files.get('photo')

    photo_path = None
    if photo:
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['COMMENT_PHOTOS_FOLDER'], filename)
        photo.save(photo_path)
        photo_path = os.path.join('static', 'comment_photos', filename)


    new_comment = TimestampComment(
        video_id=video.id,
        minutes=minutes,
        seconds=seconds,
        comment=comment_text,
        photo_path=photo_path
    )
    db.session.add(new_comment)
    db.session.commit()

    flash('Comment added successfully!', 'success')
    return redirect(url_for('video_review', video_id=video.id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_timestamp_comment(comment_id):
    comment = TimestampComment.query.get_or_404(comment_id)
    video_id = comment.video_id
    # Optional: delete photo file from storage
    if comment.photo_path and os.path.exists(comment.photo_path):
        os.remove(comment.photo_path)

    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.', 'success')
    return redirect(url_for('video_review', video_id=video_id))

@app.route('/api/editor_subject_details')
@login_required
def editor_subject_details():
    subject_name = request.args.get('subject')
    editor_id = request.args.get('editor_id')

    if not subject_name or not editor_id:
        return jsonify({"error": "Missing subject or editor_id"}), 400

    editor = Editor.query.get(editor_id)
    if not editor:
        return jsonify({"error": "Editor not found"}), 404

    headers = ["Episode", "Current Status"]
    keys = ["episode", "status"]
    results = []
    seen_episodes = set()

    def add_result(episode, status):
        if episode and episode not in seen_episodes:
            results.append({"episode": episode, "status": status})
            seen_episodes.add(episode)

    # Find videos from Video table
    videos = Video.query.filter_by(subject=subject_name, editor_id=editor_id).all()
    for v in videos:
        add_result(v.episode, v.status)

    # Find videos from EditorHandoff table
    handoffs = EditorHandoff.query.filter_by(subject=subject_name, editor_id=editor_id).all()
    for h in handoffs:
        add_result(h.episode, h.progress)

    # Find videos from RawVideo table
    raw_videos = RawVideo.query.filter_by(subject=subject_name, editor_id=editor_id).all()
    for r in raw_videos:
        add_result(r.episode, r.status)

    return jsonify({"headers": headers, "keys": keys, "results": results, "editor_name": editor.name})

@app.route('/api/new_approved_details')
@login_required
def new_approved_details():
    subject_name = request.args.get('subject')

    if not subject_name:
        return jsonify({"error": "Missing subject name"}), 400

    time_24_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    newly_approved_videos = Video.query.filter(
        Video.subject == subject_name,
        Video.status == 'Approved',
        Video.date >= time_24_hours_ago.strftime('%Y-%m-%d')
    ).all()

    results = [{'episode': v.episode, 'chapter': v.chapter} for v in newly_approved_videos]

    return jsonify({"results": results})

@app.route('/api/subject_progress_details')
@login_required
def subject_progress_details():
    subject = request.args.get('subject')

    if not subject or subject == 'undefined':
        return jsonify({"error": "Subject not specified"}), 400

    # --- Video & Handoff Table Counts (for other progress bars) ---
    approved_count = Video.query.filter_by(subject=subject, status="Approved").count()
    reviewing_count = Video.query.filter_by(subject=subject, status="Under Review").count()
    pending_count = Video.query.filter_by(subject=subject, status="Pending").count()
    ongoing_count = EditorHandoff.query.filter_by(subject=subject, progress="Ongoing").count()
    unassigned_raw_for_shooting_count = RawVideo.query.filter_by(subject=subject, status="Not Assigned").count()

    # --- Logic for the "Assigned Raw" Progress Bar ---
    # 1. Get all unique episodes that have been shot, regardless of workflow
    raw_episodes = {r[0] for r in RawVideo.query.filter_by(subject=subject).with_entities(RawVideo.episode).all()}
    handoff_episodes = {h[0] for h in EditorHandoff.query.filter_by(subject=subject).with_entities(EditorHandoff.episode).all()}
    video_episodes = {v[0] for v in Video.query.filter_by(subject=subject).with_entities(Video.episode).all()}
    
    total_shot_episodes_set = raw_episodes.union(handoff_episodes, video_episodes)
    total_shot_count = len(total_shot_episodes_set)

    # 2. Of all shot videos, find how many are truly "assigned" (i.e., not explicitly 'Not Assigned')
    explicitly_unassigned_count = RawVideo.query.filter(
        RawVideo.subject == subject, 
        RawVideo.status == "Not Assigned",
        RawVideo.episode.in_(list(total_shot_episodes_set))
    ).count() if total_shot_episodes_set else 0

    true_assigned_count = total_shot_count - explicitly_unassigned_count

    # Determine total planned episodes for the subject (for other bars)
    if subject == 'Chemistry':
        total_episodes = 26
    elif subject in ['Math', 'English']:
        total_episodes = 30
    elif subject == 'Geography':
        total_episodes = 21
    else:
        total_episodes = 25

    # --- Progress Bar Calculations ---
    # 1. Approved Progress
    approved_percentage = (approved_count / total_episodes) * 100 if total_episodes > 0 else 0
    approved_color = 'green' if approved_percentage >= 80 else 'yellow' if approved_percentage >= 30 else 'red'

    # 2. Shooting Progress
    shooting_count = (approved_count + unassigned_raw_for_shooting_count + ongoing_count + pending_count + reviewing_count)
    shooting_percentage = (shooting_count / total_episodes) * 100 if total_episodes > 0 else 0
    shooting_color = 'green' if shooting_percentage >= 80 else 'yellow' if shooting_percentage >= 30 else 'red'

    # 3. Assigned Raw Videos Progress (using the new, accurate logic)
    assigned_percentage = (true_assigned_count / total_shot_count) * 100 if total_shot_count > 0 else 0
    assigned_color = 'green' if assigned_percentage >= 100 else 'yellow' if assigned_percentage >= 50 else 'red'

    return jsonify({
        'approved_progress': {
            'count': approved_count,
            'total': total_episodes,
            'percentage': round(approved_percentage, 1),
            'color_class': approved_color
        },
        'shooting_progress': {
            'count': shooting_count,
            'total': total_episodes,
            'percentage': round(shooting_percentage, 1),
            'color_class': shooting_color
        },
        'assigned_progress': {
            'count': true_assigned_count,
            'total': total_shot_count,
            'percentage': round(assigned_percentage, 1),
            'color_class': assigned_color
        }
    })

@app.route('/reporting')
@login_required
def reporting():
    subjects = Subject.query.order_by(Subject.name).all()
    editors = Editor.query.order_by(Editor.name).all()

    subject_data = [{"id": s.id, "name": s.name} for s in subjects]
    editor_data = [{"id": e.id, "name": e.name} for e in editors]

    return render_template(
        "reporting.html",
        subjects=subject_data,
        editors=editor_data,
        current_page='reporting'
    )

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    try:
        report_type = request.form.get('report_type')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        output = io.BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')
        
        filename = f"report_{datetime.now().strftime('%Y-%m-%d')}.xlsx"

        if report_type == 'production_summary':
            filename = f"Production_Summary_{start_date_str}_to_{end_date_str}.xlsx"
            
            summary_data = []
            all_subjects = Subject.query.order_by(Subject.name).all()

            for subject in all_subjects:
                videos_in_range = Video.query.filter(Video.subject == subject.name).all()
                created_count = 0
                approved_count = 0
                
                for v in videos_in_range:
                    try:
                        v_date = v.date if isinstance(v.date, date) else datetime.strptime(v.date, '%Y-%m-%d').date()
                        if start_date <= v_date <= end_date:
                            created_count +=1
                            if v.status == 'Approved':
                                approved_count +=1
                    except (ValueError, TypeError):
                        continue

                if created_count > 0:
                     summary_data.append({
                        "Subject": subject.name,
                        "Videos Created in Period": created_count,
                        "Videos Approved in Period": approved_count,
                    })

            df = pd.DataFrame(summary_data)
            df.to_excel(writer, sheet_name='Production Summary', index=False)

        elif report_type == 'subject_deep_dive':
            subject_id = request.form.get('subject_id')
            subject = Subject.query.get(subject_id)
            filename = f"{subject.name}_Deep_Dive_{start_date_str}_to_{end_date_str}.xlsx"
            
            videos_in_range = Video.query.filter(
                Video.subject == subject.name
            ).options(joinedload(Video.editor)).order_by(Video.episode).all()
            
            subject_data = []
            for v in videos_in_range:
                 try:
                    v_date = v.date if isinstance(v.date, date) else datetime.strptime(v.date, '%Y-%m-%d').date()
                    if start_date <= v_date <= end_date:
                        subject_data.append({
                            "Episode": v.episode,
                            "Chapter": v.chapter,
                            "Final Status": v.status,
                            "Date Created": v.date,
                            "Editor": v.editor.name if v.editor else "N/A"
                        })
                 except (ValueError, TypeError):
                     continue

            df = pd.DataFrame(subject_data)
            df.to_excel(writer, sheet_name=f'{subject.name} Report', index=False)

        elif report_type == 'editor_task_log':
            editor_id = request.form.get('editor_id')
            editor = Editor.query.get(editor_id)
            filename = f"{editor.name}_Task_Log_{start_date_str}_to_{end_date_str}.xlsx"
            
            task_data = []
            handoffs = EditorHandoff.query.filter(EditorHandoff.editor_id == editor_id).all()

            for h in handoffs:
                try:
                    h_date = h.date_assigned if isinstance(h.date_assigned, date) else datetime.strptime(h.date_assigned, '%Y-%m-%d').date()
                    if start_date <= h_date <= end_date:
                        task_data.append({
                            "Date": h_date.strftime('%Y-%m-%d'),
                            "Subject": h.subject,
                            "Episode": h.episode,
                            "Task / Status Change": f"Work status became '{h.progress}'"
                        })
                except (ValueError, TypeError, AttributeError):
                    continue

            task_data.sort(key=lambda x: x['Date'], reverse=True)
            df = pd.DataFrame(task_data)
            df.to_excel(writer, sheet_name=f'{editor.name} Task Log', index=False)


        writer.close()
        output.seek(0)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        print(f"Error generating report: {e}")
        flash("An error occurred while generating the report.", "error")
        return redirect(url_for('reporting'))

@app.route('/api/dashboard_details')
@login_required
def dashboard_details():
    status = request.args.get('status')

    def get_user_info(user):
        if not user or not hasattr(user, 'name'):
            return 'N/A'
        
        pic_url = url_for('static', filename='images/default_avatar.png')
        if hasattr(user, 'profile_picture') and user.profile_picture:
            pic_url = url_for('serve_profile_image', filename=user.profile_picture)

        return {'name': user.name, 'pic': pic_url}

    headers = []
    keys = []
    results = []

    if status == 'subjects':
        headers = ['Subject', 'Supervisor', 'Progress']
        keys = ['subject', 'supervisor', 'percentage']
        
        # Pre-fetch all video counts grouped by subject and status
        video_counts_query = db.session.query(
            Video.subject,
            Video.status,
            func.count(Video.id)
        ).group_by(Video.subject, Video.status).all()
        
        # Organize counts for easy lookup
        counts_by_subject = {}
        for subject_name, video_status, count in video_counts_query:
            if subject_name not in counts_by_subject:
                counts_by_subject[subject_name] = {}
            counts_by_subject[subject_name][video_status] = count

        # Fetch all subjects and their supervisors
        all_subjects = Subject.query.options(db.joinedload(Subject.supervisor)).order_by(Subject.name).all()

        for s in all_subjects:
            subject_name = s.name
            if subject_name == 'Chemistry':
                total_episodes = 26
            elif subject_name in ['Math', 'English']:
                total_episodes = 30
            elif subject_name == 'Geography':
                total_episodes = 21
            else:
                total_episodes = 25

            counts = counts_by_subject.get(s.name, {})
            pending = counts.get('Pending', 0)
            review = counts.get('Under Review', 0)
            approved = counts.get('Approved', 0)
            
            percentage = 0
            if total_episodes > 0:
                percentage = round((approved / total_episodes) * 100)

            # Determine color for progress bar
            color_class = 'green' if percentage == 100 else 'yellow' if percentage > 50 else 'red'

            results.append({
                'subject': s.name,
                'supervisor': get_user_info(s.supervisor),
                'total': total_episodes,
                'pending': pending,
                'review': review,
                'approved': approved,
                'percentage': {'value': percentage, 'color_class': color_class}
            })

        # Sort results by progress percentage in descending order
        results.sort(key=lambda x: x['percentage']['value'], reverse=True)

    elif status in ['pending', 'under_review', 'approved']:
        status_map = {
            'pending': 'Pending',
            'under_review': 'Under Review',
            'approved': 'Approved'
        }
        actual_status = status_map[status]
        
        headers = ['Subject', 'Episode', 'Chapter', 'Editor', 'Date']
        keys = ['subject', 'episode', 'chapter', 'editor', 'date']
        
        videos = Video.query.filter_by(status=actual_status).options(db.joinedload(Video.editor)).order_by(Video.date.desc()).all()
        
        results = [{
            'subject': v.subject,
            'episode': v.episode,
            'chapter': v.chapter,
            'editor': get_user_info(v.editor),
            'date': v.date
        } for v in videos]

    elif status == 'schedule':
        headers = ['Supervisor', 'Day', 'Time Range', 'Assigned Subjects']
        keys = ['supervisor', 'day', 'time_range', 'subjects']
        
        query = db.session.query(SupervisorSchedule).options(
            db.joinedload(SupervisorSchedule.supervisor).joinedload(Supervisor.subjects)
        )

        # If the current user is a supervisor, only show their own schedule
        if current_user.role == 'supervisor':
            supervisor = Supervisor.query.filter(func.lower(Supervisor.name) == func.lower(current_user.username)).first()
            if supervisor:
                query = query.filter(SupervisorSchedule.supervisor_id == supervisor.id)
            else:
                # If no matching supervisor profile, show no results
                query = query.filter(False)
        
        schedules = query.order_by(
            case(
                (SupervisorSchedule.day_of_week == 'Monday', 1),
                (SupervisorSchedule.day_of_week == 'Tuesday', 2),
                (SupervisorSchedule.day_of_week == 'Wednesday', 3),
                (SupervisorSchedule.day_of_week == 'Thursday', 4),
                (SupervisorSchedule.day_of_week == 'Friday', 5),
                (SupervisorSchedule.day_of_week == 'Saturday', 6),
                (SupervisorSchedule.day_of_week == 'Sunday', 7),
                else_=8
            ),
            SupervisorSchedule.start_time
        ).all()
        
        results = [{
            'supervisor': get_user_info(s.supervisor),
            'day': s.day_of_week,
            'time_range': f"{s.start_time.strftime('%I:%M %p').lstrip('0')} - {s.end_time.strftime('%I:%M %p').lstrip('0')}",
            'subjects': ', '.join([subj.name for subj in s.supervisor.subjects]) or 'None'
        } for s in schedules]

    return jsonify({'headers': headers, 'keys': keys, 'results': results})

# ----------------- CLI Commands -----------------
import click
from flask.cli import with_appcontext

@app.cli.command("create-admin")
@with_appcontext
@click.argument("username")
@click.argument("password")
def create_admin(username, password):
    """Creates a new operator admin user."""
    existing_user = Users.query.filter_by(username=username).first()
    if existing_user:
        print(f"Error: User '{username}' already exists.")
        return

    hashed_pw = generate_password_hash(password)
    admin = Users(username=username, password=hashed_pw, role='operator_admin')
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user '{username}' created successfully.")


@app.cli.command("clean-last-seen")
@with_appcontext
def clean_last_seen():
    """Sets last_seen to NULL for users who have never logged in."""
    # Find all user IDs that have a 'Logged in' action in the log
    logged_in_user_ids = db.session.query(ActivityLog.user_id).filter_by(action='Logged in').distinct().all()
    # The result is a list of tuples, so we flatten it
    logged_in_user_ids = [item[0] for item in logged_in_user_ids]

    # Find all users who are NOT in the list of logged-in users
    # AND have a non-null value in `last_seen` (which is the bad data)
    users_to_clean = Users.query.filter(
        Users.id.notin_(logged_in_user_ids),
        Users.last_seen.isnot(None)
    ).all()

    if not users_to_clean:
        print("No users needed cleaning. Database is already consistent.")
        return

    cleaned_count = 0
    for user in users_to_clean:
        user.last_seen = None
        cleaned_count += 1
    
    db.session.commit()
    print(f"Successfully cleaned {cleaned_count} user(s). Their 'last_seen' status has been reset.")


@app.cli.command("sync-last-seen")
@with_appcontext
def sync_last_seen():
    """
    Synchronizes the Users.last_seen column with the actual last login
    time from the ActivityLog table. This is a one-time command to fix bad data.
    """
    print("Starting synchronization of last_seen timestamps...")

    # Get a dictionary of the true last login time for each user
    true_last_logins = dict(db.session.query(
        ActivityLog.user_id, 
        func.max(ActivityLog.timestamp)
    ).filter(ActivityLog.action == 'Logged in').group_by(ActivityLog.user_id).all())

    all_users = Users.query.all()
    updated_count = 0
    
    for user in all_users:
        true_last_login = true_last_logins.get(user.id)
        
        # If the user's last_seen is different from their true last login, update it.
        # This also handles cases where last_seen is set but should be NULL.
        if user.last_seen != true_last_login:
            user.last_seen = true_last_login
            updated_count += 1
            
    if updated_count > 0:
        db.session.commit()
        print(f"Synchronization complete. {updated_count} user(s) were updated.")
    else:
        print("All user timestamps are already synchronized. No changes made.")


@app.route('/bulk_add_raw_videos_manual', methods=['POST'])
def bulk_add_raw_videos_manual():
    """
    Handles bulk insertion of raw videos from manual table entry.
    """
    data = request.get_json()
    videos_to_add = data.get('videos', [])
    
    if not videos_to_add:
        return jsonify(success=False, error="No video data provided."), 400

    added_count = 0
    skipped_count = 0
    
    # Pre-load existing raw videos for efficient duplicate checking
    all_raws = RawVideo.query.with_entities(RawVideo.subject, RawVideo.episode).all()
    existing_raw_keys = {
        (r.subject.strip().lower(), normalize_episode(r.episode)) for r in all_raws
    }

    try:
        for video_data in videos_to_add:
            subject = video_data.get('subject')
            episode = video_data.get('episode')
            chapter = video_data.get('chapter')
            date_str = video_data.get('date')

            if not all([subject, episode, chapter, date_str]):
                skipped_count += 1
                continue

            # Check for duplicates
            normalized_ep = normalize_episode(episode)
            key = (subject.strip().lower(), normalized_ep)

            if key in existing_raw_keys:
                skipped_count += 1
                continue

            # Convert date string...
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                skipped_count += 1
                continue
            
            new_video = RawVideo(
                subject=subject.strip().title(),
                episode=normalized_ep,
                chapter=chapter.strip(),
                date=date_obj,
                status='Not Assigned'
            )
            db.session.add(new_video)
            
            # Add to our set to prevent duplicates within the same upload batch
            existing_raw_keys.add(key)
            added_count += 1
        
        db.session.commit()
        
        flash_message = ""
        if added_count > 0:
            flash_message += f"Successfully added {added_count} new raw videos. "
        if skipped_count > 0:
            flash_message += f"Skipped {skipped_count} duplicates or invalid rows."
        
        if flash_message:
            flash(flash_message.strip(), 'success' if added_count > 0 else 'warning')

        return jsonify(success=True, count=added_count, skipped=skipped_count)

    except Exception as e:
        db.session.rollback()
        print(f"Error during bulk manual add: {e}")
        return jsonify(success=False, error=str(e)), 500


@app.route('/delete_raw_video/<int:raw_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def delete_raw_video(raw_id):
    try:
        raw_video = RawVideo.query.get(raw_id)
        if not raw_video:
            return jsonify({"success": False, "error": "Raw video not found"}), 404

        # To maintain data integrity, also delete the corresponding
        # EditorHandoff record if it exists.
        handoff = EditorHandoff.query.filter_by(
            subject=raw_video.subject,
            episode=raw_video.episode
        ).first()

        if handoff:
            db.session.delete(handoff)

        # Also delete the corresponding Video record if it exists
        video = Video.query.filter_by(
            subject=raw_video.subject,
            episode=raw_video.episode
        ).first()

        if video:
            db.session.delete(video)

        db.session.delete(raw_video)
        db.session.commit()

        # The frontend will show a success popup, no flash needed here.
        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting raw video: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/my_comments')
@login_required
@roles_required('editor', 'operator_admin', 'manager')
def my_comments():
    """
    Shows a personalized page for an editor with all review comments
    related to their assigned episodes.
    For admins/managers, it shows all comments.
    """
    comments_to_render = []
    page_title_name = ""

    # Fetch all comments and create a base mapping
    all_comments = ReviewCommentLog.query.order_by(ReviewCommentLog.timestamp.desc()).all()
    all_handoffs = EditorHandoff.query.options(joinedload(EditorHandoff.editor)).all()
    
    handoff_map = {
        (h.subject.lower().strip(), h.episode): h for h in all_handoffs
    }

    if current_user.role in ['operator_admin', 'manager']:
        page_title_name = "All Editors (Admin View)"
        comments_to_process = all_comments
    else: # editor role
        editor = Editor.query.filter(func.lower(Editor.name) == func.lower(current_user.username)).first()
        if not editor:
            flash("Could not find an editor profile linked to your user account.", "warning")
            return render_template("my_comments.html", comments=[], editor_name=current_user.username, subjects=[])

        page_title_name = f"you, {editor.name}!"
        editor_work_keys = {(h.subject.lower().strip(), h.episode) for h in all_handoffs if h.editor_id == editor.id}
        
        comments_to_process = [
            c for c in all_comments 
            if (c.subject.lower().strip(), normalize_episode(c.episode)) in editor_work_keys
        ]
        
    for comment in comments_to_process:
        normalized_episode = normalize_episode(comment.episode)
        key = (comment.subject.lower().strip(), normalized_episode)
        handoff = handoff_map.get(key)

        comment.filename = os.path.basename(comment.docx_file_path)
        comment.status = handoff.progress if handoff else None
        
        editor_obj = handoff.editor if handoff else None
        
        if editor_obj:
            pic_url = url_for("serve_profile_image", filename=editor_obj.profile_picture or "default.png")
            comment.editor_info = {'name': editor_obj.name, 'profile_picture_url': pic_url}
        else:
            pic_url = url_for("serve_profile_image", filename="default.png")
            comment.editor_info = {'name': 'Unknown', 'profile_picture_url': pic_url}

        comments_to_render.append(comment)

    # Get unique subjects for the filter dropdown
    subjects = sorted(list({c.subject for c in comments_to_render}))

    return render_template(
        "my_comments.html",
        comments=comments_to_render,
        editor_name=page_title_name,
        subjects=subjects,
        current_page='my_comments',
        now=datetime.now(timezone.utc)
    )

@app.route('/notifications/mark-as-read', methods=['POST'])
@login_required
def mark_notifications_as_read():
    """
    Marks all unread notifications for the current user as read.
    Triggered when the user opens the notification center.
    """
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        print(f"Error marking notifications as read: {e}")
        return jsonify(success=False, error=str(e)), 500


@app.route('/resubmit_for_review/<int:comment_id>', methods=['POST'])
@login_required
@roles_required('editor')
def resubmit_for_review(comment_id):
    """
    Allows an editor to submit a 'Re-editing' task for approval.
    """
    comment = ReviewCommentLog.query.get_or_404(comment_id)

    # Normalize episode from comment for matching
    normalized_episode = normalize_episode(comment.episode)
    subject = comment.subject

    # Find the corresponding handoff
    handoff = EditorHandoff.query.filter_by(
        subject=subject,
        episode=normalized_episode
    ).first()

    if not handoff:
        return jsonify({"success": False, "error": "Could not find a matching handoff for this episode."}), 404
    
    # Check if the handoff belongs to the current user
    if handoff.editor.name.lower() != current_user.username.lower():
        return jsonify({"success": False, "error": "You are not authorized to modify this episode."}), 403

    # Only allow this action if the progress is 'Re-editing'
    if handoff.progress != "Re-editing":
        return jsonify({"success": False, "error": f"This action is not available. The current status is '{handoff.progress}'."}), 400
    
    # Check if a pending submission already exists for this comment
    existing_submission = ReviewSubmission.query.filter_by(comment_log_id=comment.id, status='pending').first()
    if existing_submission:
        return jsonify({"success": False, "error": "This episode is already awaiting approval."}), 400

    # --- Create Submission Record ---
    new_submission = ReviewSubmission(
        comment_log_id=comment.id,
        submitted_by_user_id=current_user.id
    )
    db.session.add(new_submission)

    # --- Update Handoff Status to show it's waiting ---
    handoff.progress = "Awaiting Approval"

    try:
        db.session.commit()
        # --- Notify Admins/Managers ---
        admins = Users.query.filter(Users.role.in_(['operator_admin', 'manager'])).all()
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                message=f"<strong>'{subject} - Ep {normalized_episode}'</strong> was sent for approval by {current_user.username}.",
                notification_type='submission'
            )
            db.session.add(notification)
        db.session.commit()
        
        flash("Episode submitted for approval.", "comment_success")
        return jsonify({"success": True, "message": "Episode submitted for approval."})
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "comment_danger")
        return jsonify({"success": False, "error": f"An error occurred: {str(e)}"}), 500


@app.route('/user_promo')
@login_required
@roles_required('operator_admin')
def user_promo():
    """Renders the new user management and promotion page."""
    # Get the last login for each user from the ActivityLog
    last_logins = db.session.query(
        ActivityLog.user_id, 
        func.max(ActivityLog.timestamp).label('last_login_time')
    ).filter(ActivityLog.action == 'Logged in').group_by(ActivityLog.user_id).subquery()

    # Join users with their last login time
    users_with_logins = db.session.query(
        Users, 
        last_logins.c.last_login_time
    ).outerjoin(last_logins, Users.id == last_logins.c.user_id).order_by(Users.username).all()

    # Process results into a more usable format for the template
    processed_users = []
    for user, last_login_time in users_with_logins:
        user.last_login = last_login_time
        # Check for recent activity
        if user.last_seen and (datetime.now(timezone.utc) - user.last_seen) < timedelta(minutes=10):
            user.is_currently_active = True
        else:
            user.is_currently_active = False
        processed_users.append(user)
    
    available_roles = ['editor', 'supervisor', 'manager', 'operator_admin']
    return render_template(
        'user_promo.html',
        users=processed_users,
        available_roles=available_roles,
        current_page='user_promo',
        now=datetime.now(timezone.utc)
    )


@app.route('/user_promo/add_user', methods=['POST'])
@login_required
@roles_required('operator_admin')
def add_user_promo():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role')
    avatar_file = request.files.get('avatar')

    if not all([username, password, role]):
        return jsonify({'success': False, 'error': 'Missing username, password, or role.'}), 400

    if Users.query.filter(func.lower(Users.username) == func.lower(username)).first():
        return jsonify({'success': False, 'error': 'Username already exists.'}), 409

    hashed_pw = generate_password_hash(password)
    new_user = Users(username=username, password=hashed_pw, role=role)

    if avatar_file and avatar_file.filename:
        pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
        os.makedirs(pics_folder, exist_ok=True)
        filename = secure_filename(f"user_{username}_{avatar_file.filename}")
        avatar_file.save(os.path.join(pics_folder, filename))
        new_user.profile_picture = filename

    db.session.add(new_user)
    db.session.commit()
    
    log_activity(f"Added new user: {username} with role {role}.")
    
    avatar_url = url_for('serve_profile_image', filename=new_user.profile_picture or 'default.png')

    return jsonify({
        'success': True, 
        'message': f'User {username} created successfully.',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'role': new_user.role,
            'roleDisplay': new_user.role.replace('_', ' ').title(),
            'avatar_url': avatar_url
        }
    }), 201


@app.route('/user_promo/update_user/<int:user_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def update_user_promo(user_id):
    user = Users.query.get_or_404(user_id)
    new_username = request.form.get('username', '').strip()
    new_role = request.form.get('role')
    avatar_file = request.files.get('avatar')
    
    if not new_username or not new_role:
        return jsonify({'success': False, 'error': 'Username and role cannot be empty.'}), 400

    # Check if another user already has the new username
    existing_user = Users.query.filter(func.lower(Users.username) == func.lower(new_username), Users.id != user_id).first()
    if existing_user:
        return jsonify({'success': False, 'error': 'That username is already taken.'}), 409

    # Check if we are demoting the last admin
    if user.id == current_user.id and user.role == 'operator_admin' and new_role != 'operator_admin':
        admin_count = Users.query.filter_by(role='operator_admin').count()
        if admin_count <= 1:
            return jsonify({'success': False, 'error': 'Cannot change the role of the only administrator.'}), 403
            
    user.username = new_username
    user.role = new_role

    if avatar_file and avatar_file.filename:
        # Delete old avatar if it exists
        if user.profile_picture:
            old_path = os.path.join(app.root_path, 'static', 'profile_pics', user.profile_picture)
            if os.path.exists(old_path):
                os.remove(old_path)
        
        # Save new avatar
        pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
        filename = secure_filename(f"user_{user.id}_{avatar_file.filename}")
        avatar_file.save(os.path.join(pics_folder, filename))
        user.profile_picture = filename

    db.session.commit()
    
    log_activity(f"Updated user: {user.username} (ID: {user_id}).")
    
    avatar_url = url_for('serve_profile_image', filename=user.profile_picture or 'default.png')

    return jsonify({
        'success': True,
        'message': 'User updated successfully.',
        'userData': {
            'username': user.username,
            'role': user.role,
            'roleDisplay': user.role.replace('_', ' ').title(),
            'avatar_url': avatar_url
        }
    })


@app.route('/user_promo/delete_user/<int:user_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def delete_user_promo(user_id):
    user = Users.query.get_or_404(user_id)

    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'You cannot delete your own account.'}), 403

    if user.role == 'operator_admin':
        admin_count = Users.query.filter_by(role='operator_admin').count()
        if admin_count <= 1:
            return jsonify({'success': False, 'error': 'Cannot delete the only administrator.'}), 403
    
    db.session.delete(user)
    db.session.commit()
    
    log_activity(f"Deleted user: {user.username} (ID: {user_id}).")
    return jsonify({'success': True, 'message': f'User {user.username} has been deleted.'})


@app.route('/user_promo/reset_password/<int:user_id>', methods=['POST'])
@login_required
@roles_required('operator_admin')
def reset_user_password(user_id):
    user = Users.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'You cannot reset your own password this way.'}), 403

    user.password_reset_required = True
    db.session.commit()
    
    log_activity(f"Triggered password reset for user: {user.username} (ID: {user_id}).")
    return jsonify({'success': True, 'message': f"Password for {user.username} has been reset. They will be required to set a new one on their next login."})


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password_request():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = Users.query.filter(func.lower(Users.username) == func.lower(username)).first()

        if user and user.password_reset_required:
            # Log them in temporarily to proceed to the reset page
            session['force_password_reset_user_id'] = user.id
            return redirect(url_for('force_password_reset'))
        
        elif user and not user.password_reset_required:
            flash("Your password has not been reset by an admin. Please ask an admin for help.", 'danger')
        
        else:
            flash("Username not found.", 'danger')
        
        return redirect(url_for('forgot_password_request'))

    return render_template('forgot_password_request.html')


@app.before_request
def before_request_callback():
    if current_user.is_authenticated:
        # If a password reset is required, intercept all requests except the reset page itself.
        if getattr(current_user, 'password_reset_required', False) and \
           request.endpoint not in ['force_password_reset', 'static', 'logout']:
            return redirect(url_for('force_password_reset'))

        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()


def log_activity(action_string):
    """Helper function to log user activity."""
    if not current_user.is_authenticated:
        return
    try:
        log = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action_string,
            status="Success",
            is_admin=current_user.is_admin,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
    except Exception as e:
        print(f"Error logging activity: {e}")


@app.route('/force_password_reset', methods=['GET', 'POST'])
def force_password_reset():
    user = None
    # Case 1: User is not logged in, came from forgot password page
    if 'force_password_reset_user_id' in session:
        user = Users.query.get(session['force_password_reset_user_id'])
    # Case 2: User is already logged in and was redirected here
    elif current_user.is_authenticated and current_user.password_reset_required:
        user = current_user
    
    # If we couldn't find a user who needs a password reset, redirect to login
    if not user or not user.password_reset_required:
        session.pop('force_password_reset_user_id', None)
        flash("You are not authorized to access this page.", 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            flash("Passwords do not match or are empty.", 'danger')
            return render_template('force_password_reset.html', user=user)
        
        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.", 'danger')
            return render_template('force_password_reset.html', user=user)

        user.password = generate_password_hash(new_password)
        user.password_reset_required = False
        db.session.commit()

        # Clean up session key if it exists
        session.pop('force_password_reset_user_id', None)
        
        # Log the user in to establish a new session
        login_user(user)
        
        # Log the successful password change
        try:
            # We log this as the user who just reset their password
            log_activity("Completed a password reset.")
        except Exception as e:
            # This shouldn't fail, but good to have a safeguard
            print(f"Error logging activity for password reset: {e}")
        
        # --- Admin Notification Logic ---
        try:
            admins = Users.query.filter_by(role='operator_admin').all()
            notification_message = f"User '{user.username}' has successfully reset their password and logged in."
            for admin in admins:
                # Create a notification for each admin
                notification = Notification(
                    user_id=admin.id,
                    message=notification_message,
                    notification_type='password_reset'
                )
                db.session.add(notification)
            db.session.commit()
        except Exception as e:
            print(f"Error creating password reset notification: {e}")
            db.session.rollback() # Rollback notification transaction on error

        flash("Password updated successfully. You are now logged in.", 'success')
        return redirect(url_for('dashboard_home'))

    return render_template('force_password_reset.html', user=user)


@app.route('/activity_log')
@login_required
@roles_required('operator_admin', 'manager')
def activity_log():
    """Renders a page with all activity logs."""
    # Fetch logs, newest first
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template(
        'activity_log.html',
        logs=logs,
        current_page='activity_log'
    )


@app.route('/review_submissions')
@login_required
@roles_required('operator_admin', 'manager')
def review_submissions():
    """Renders the page for reviewing editor submissions."""
    submissions = ReviewSubmission.query.filter_by(status='pending').order_by(ReviewSubmission.submitted_at.desc()).all()
    return render_template(
        'review_submissions.html',
        submissions=submissions,
        current_page='review_submissions'
    )


@app.route('/submissions/<action>/<int:submission_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def handle_submission(action, submission_id):
    submission = ReviewSubmission.query.get_or_404(submission_id)
    if submission.status != 'pending':
        return jsonify(success=False, error="This submission has already been reviewed."), 400

    handoff = EditorHandoff.query.filter_by(
        subject=submission.comment_log.subject,
        episode=submission.comment_log.episode
    ).first()

    if not handoff:
        return jsonify(success=False, error="Associated handoff not found."), 404

    submission.reviewed_by_user_id = current_user.id
    submission.reviewed_at = datetime.now(timezone.utc)

    if action == 'allow':
        submission.status = 'allowed'
        handoff.progress = 'Finished'
        
        video = Video.query.filter_by(subject=handoff.subject, episode=handoff.episode).first()
        if video:
            video.status = "Under Review"
        else:
            video = Video(
                subject=handoff.subject, episode=handoff.episode, chapter=handoff.chapter or "",
                status="Under Review", date=date.today(), editor_id=handoff.editor_id
            )
            db.session.add(video)
        
        log_activity(f"Allowed submission for {handoff.subject} - Ep {handoff.episode}")

    elif action == 'reject':
        submission.status = 'rejected'
        handoff.progress = 'Re-editing'
        log_activity(f"Rejected submission for {handoff.subject} - Ep {handoff.episode}")
    
    else:
        return jsonify(success=False, error="Invalid action."), 400

    try:
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=str(e)), 500


@app.route('/notifications_page')
@login_required
def notifications_page():
    """Renders a page with all of the user's notifications."""
    # Query all notifications for the current user, newest first.
    # We use joinedload to efficiently fetch related comment and user data.
    notifications = Notification.query.options(
        joinedload(Notification.comment),
        joinedload(Notification.user)
    ).filter(
        Notification.user_id == current_user.id
    ).order_by(
        Notification.created_at.desc()
    ).all()

    return render_template(
        'notifications_page.html',
        notifications=notifications,
        current_page='notifications'
    )


@app.route('/clear_comment/<int:item_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'supervisor')
def clear_comment(item_id):
    try:
        item = db.session.get(QuickReviewItem, item_id)
        if not item:
            return jsonify(success=False, error="Item not found"), 404

        # --- 1. Delete File and Log ---
        if item.comment_file_name:
            log_entry = ReviewCommentLog.query.filter_by(docx_file_path=item.comment_file_name).first()

            if log_entry:
                # Delete related ReviewSubmission records first to avoid foreign key constraint
                ReviewSubmission.query.filter_by(comment_log_id=log_entry.id).delete()
                
                # Nullify references in Notifications to avoid foreign key errors
                Notification.query.filter_by(comment_id=log_entry.id).update({'comment_id': None})
                
                # Now delete the log entry
                db.session.delete(log_entry)

            # Delete the physical file
            file_path = os.path.join(app.root_path, app.config['COMMENT_UPLOAD_FOLDER'], item.comment_file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
            
            item.comment_file_name = None

        # --- 2. Un-review the item and sync statuses ---
        item.is_reviewed = False
        
        video = Video.query.filter_by(subject=item.subject, episode=item.episode).first()
        if video:
            video.status = "Under Review"

        handoff = EditorHandoff.query.filter_by(subject=item.subject, episode=item.episode).first()
        if handoff:
            handoff.progress = "Finished"
        
        db.session.commit()
        
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        print(f"Error clearing comment: {e}")
        return jsonify(success=False, error=str(e)), 500


class ReviewSubmission(db.Model):
    __tablename__ = 'review_submissions'
    id = db.Column(db.Integer, primary_key=True)
    comment_log_id = db.Column(db.Integer, db.ForeignKey('review_comments_log.id'), nullable=False)
    submitted_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(50), default='pending', nullable=False)  # pending, allowed, rejected
    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    comment_log = db.relationship('ReviewCommentLog', backref='submission')
    submitted_by = db.relationship('Users', foreign_keys=[submitted_by_user_id], backref='submissions_made')
    reviewed_by = db.relationship('Users', foreign_keys=[reviewed_by_user_id], backref='submissions_reviewed')

    

# ----------------- TEST ROUTE -----------------
@app.route('/test_notification')
@login_required
@roles_required('operator_admin')
def test_notification():
    """Creates a test submission notification for the current admin user."""
    try:
        notification = Notification(
            user_id=current_user.id,
            message=f"<strong>'Test Subject - Ep Test'</strong> was sent for approval by TestUser.",
            notification_type='submission'
        )
        db.session.add(notification)
        db.session.commit()
        flash("Test notification sent successfully! You should see a pop-up.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to send test notification: {e}", 'danger')
        
    return redirect(request.referrer or url_for('dashboard_home'))
# ----------------- END TEST ROUTE -----------------


@app.route('/additions', methods=['GET', 'POST'])
@login_required
@roles_required('operator_admin', 'manager')
def additions():
    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'add_subject':
            subject_name = request.form.get('subject_name', '').strip()
            if subject_name and not Subject.query.filter(func.lower(Subject.name) == func.lower(subject_name)).first():
                new_subject = Subject(name=subject_name)
                db.session.add(new_subject)
                db.session.commit()
                flash(f"Subject '{subject_name}' added successfully.", 'success')
            else:
                flash(f"Subject '{subject_name}' is empty or already exists.", 'danger')

        elif form_type == 'add_supervisor':
            supervisor_name = request.form.get('supervisor_name', '').strip()
            avatar_file = request.files.get('supervisor_avatar_file')

            if supervisor_name and not Supervisor.query.filter(func.lower(Supervisor.name) == func.lower(supervisor_name)).first():
                filename = None
                if avatar_file and avatar_file.filename:
                    pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
                    os.makedirs(pics_folder, exist_ok=True)
                    
                    filename = secure_filename(avatar_file.filename)
                    avatar_file.save(os.path.join(pics_folder, filename))

                new_supervisor = Supervisor(name=supervisor_name, profile_picture=filename)
                db.session.add(new_supervisor)
                db.session.commit()
                flash(f"Supervisor '{supervisor_name}' added successfully.", 'success')
            else:
                flash(f"Supervisor '{supervisor_name}' is empty or already exists.", 'danger')
        
        elif form_type == 'add_editor':
            editor_name = request.form.get('editor_name', '').strip()
            avatar_file = request.files.get('avatar_file')
            
            if editor_name and not Editor.query.filter(func.lower(Editor.name) == func.lower(editor_name)).first():
                filename = None
                if avatar_file and avatar_file.filename:
                    # Ensure the folder exists
                    pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
                    os.makedirs(pics_folder, exist_ok=True)
                    
                    filename = secure_filename(avatar_file.filename)
                    avatar_file.save(os.path.join(pics_folder, filename))

                new_editor = Editor(name=editor_name, profile_picture=filename)
                db.session.add(new_editor)
                db.session.commit()
                flash(f"Editor '{editor_name}' added successfully.", 'success')
            else:
                flash(f"Editor '{editor_name}' is empty or already exists.", 'danger')

        return redirect(url_for('additions'))

    subjects = Subject.query.order_by(Subject.name).all()
    supervisors = Supervisor.query.order_by(Supervisor.name).all()
    editors = Editor.query.order_by(Editor.name).all()
    schedules = SupervisorSchedule.query.options(
        joinedload(SupervisorSchedule.supervisor)
    ).order_by(SupervisorSchedule.day_of_week, SupervisorSchedule.start_time).all()
    
    return render_template(
        'additions.html', 
        subjects=subjects, 
        supervisors=supervisors,
        editors=editors,
        schedules=schedules,
        current_page='additions'
    )


@app.route('/add-schedule', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def add_schedule():
    supervisor_id = request.form.get('supervisor_id')
    days_of_week = request.form.getlist('day_of_week')
    start_time_str = request.form.get('start_time')
    end_time_str = request.form.get('end_time')

    if not all([supervisor_id, days_of_week, start_time_str, end_time_str]):
        flash("All schedule fields, including at least one day, are required.", 'danger')
        return redirect(url_for('additions'))

    try:
        start_time = datetime.strptime(start_time_str, '%H:%M').time()
        end_time = datetime.strptime(end_time_str, '%H:%M').time()
    except ValueError:
        flash("Invalid time format. Please use HH:MM.", 'danger')
        return redirect(url_for('additions'))

    for day in days_of_week:
        new_schedule = SupervisorSchedule(
            supervisor_id=supervisor_id,
            day_of_week=day,
            start_time=start_time,
            end_time=end_time
        )
        db.session.add(new_schedule)
    
    db.session.commit()
    flash(f"Schedule added for {len(days_of_week)} day(s).", 'success')
    return redirect(url_for('additions'))


@app.route('/delete-schedule/<int:schedule_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def delete_schedule(schedule_id):
    schedule = SupervisorSchedule.query.get_or_404(schedule_id)
    try:
        db.session.delete(schedule)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete-subject/<int:subject_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    subject_name = subject.name
    try:
        db.session.delete(subject)
        db.session.commit()
        flash(f"Subject '{subject_name}' has been deleted.", 'danger')
        return jsonify({'success': True})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'error': f"Cannot delete '{subject_name}' because it is being used by videos or handoffs."}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete-supervisor/<int:supervisor_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def delete_supervisor(supervisor_id):
    supervisor = Supervisor.query.get_or_404(supervisor_id)
    supervisor_name = supervisor.name
    try:
        if supervisor.profile_picture:
            try:
                pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
                os.remove(os.path.join(pics_folder, supervisor.profile_picture))
            except FileNotFoundError:
                pass
        
        db.session.delete(supervisor)
        db.session.commit()
        flash(f"Supervisor '{supervisor_name}' has been deleted.", 'danger')
        return jsonify({'success': True})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'error': f"Cannot delete '{supervisor_name}' because they are assigned to subjects or materials."}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete-editor/<int:editor_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def delete_editor(editor_id):
    editor = Editor.query.get_or_404(editor_id)
    editor_name = editor.name
    try:
        if editor.profile_picture:
            try:
                pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
                os.remove(os.path.join(pics_folder, editor.profile_picture))
            except FileNotFoundError:
                pass

        db.session.delete(editor)
        db.session.commit()
        flash(f"Editor '{editor_name}' has been deleted.", 'danger')
        return jsonify({'success': True})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'error': f"Cannot delete '{editor_name}' because they are assigned to videos or handoffs."}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/edit-subject/<int:subject_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def edit_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    new_name = request.form.get('name', '').strip()

    if not new_name:
        return jsonify({'success': False, 'error': 'Subject name cannot be empty.'}), 400

    existing_subject = Subject.query.filter(func.lower(Subject.name) == func.lower(new_name), Subject.id != subject_id).first()
    if existing_subject:
        return jsonify({'success': False, 'error': f"Subject name '{new_name}' already exists."}), 409
        
    subject.name = new_name
    db.session.commit()
    flash(f"Subject '{new_name}' updated successfully.", 'success')
    return jsonify({'success': True})

def _edit_person(person_id, person_type):
    model = Supervisor if person_type == 'supervisor' else Editor
    person = model.query.get_or_404(person_id)
    
    new_name = request.form.get('name', '').strip()
    avatar_file = request.files.get('avatar_file')

    if not new_name:
        return jsonify({'success': False, 'error': 'Name cannot be empty.'}), 400

    existing_person = model.query.filter(func.lower(model.name) == func.lower(new_name), model.id != person_id).first()
    if existing_person:
        return jsonify({'success': False, 'error': f"Name '{new_name}' already exists."}), 409

    person.name = new_name
    
    if avatar_file and avatar_file.filename:
        if person.profile_picture and person.profile_picture != 'default.png':
            try:
                old_path = os.path.join(app.root_path, 'static', 'profile_pics', person.profile_picture)
                if os.path.exists(old_path):
                    os.remove(old_path)
            except Exception as e:
                print(f"Error deleting old avatar: {e}")

        pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
        new_filename = secure_filename(avatar_file.filename)
        avatar_file.save(os.path.join(pics_folder, new_filename))
        person.profile_picture = new_filename

    db.session.commit()
    flash(f"{person_type.title()} '{new_name}' updated successfully.", 'success')
    return jsonify({'success': True})

@app.route('/edit-supervisor/<int:supervisor_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def edit_supervisor(supervisor_id):
    return _edit_person(supervisor_id, 'supervisor')

@app.route('/edit-editor/<int:editor_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def edit_editor(editor_id):
    return _edit_person(editor_id, 'editor')

@app.route('/link-supervisor/<int:subject_id>', methods=['POST'])
@login_required
@roles_required('operator_admin', 'manager')
def link_supervisor(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    data = request.get_json()
    supervisor_id = data.get('supervisor_id')

    if not supervisor_id:
        return jsonify({'success': False, 'error': 'Supervisor ID is missing.'}), 400

    supervisor = Supervisor.query.get_or_404(supervisor_id)
    
    subject.supervisor = supervisor
    db.session.commit()
    
    flash(f"Supervisor '{supervisor.name}' linked to subject '{subject.name}'.", 'success')
    return jsonify({'success': True})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # --- Handle Avatar Upload ---
        avatar_file = request.files.get('avatar')
        if avatar_file and avatar_file.filename:
            # Delete old avatar if it's not the default one
            if current_user.profile_picture:
                old_path = os.path.join(app.root_path, 'static', 'profile_pics', current_user.profile_picture)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception as e:
                        print(f"Error deleting old avatar: {e}")

            # Save new avatar
            pics_folder = os.path.join(app.root_path, 'static', 'profile_pics')
            os.makedirs(pics_folder, exist_ok=True)
            
            # Create a unique filename to avoid conflicts
            filename = secure_filename(f"user_{current_user.id}_{avatar_file.filename}")
            avatar_file.save(os.path.join(pics_folder, filename))
            current_user.profile_picture = filename
            flash('Profile picture updated successfully.', 'success')

        # --- Handle Username Change ---
        new_username = request.form.get('username', '').strip()
        if new_username and new_username != current_user.username:
            existing_user = Users.query.filter(func.lower(Users.username) == func.lower(new_username)).first()
            if existing_user:
                flash('That username is already taken.', 'danger')
            else:
                old_username = current_user.username
                current_user.username = new_username
                log_activity(f"Changed username from '{old_username}' to '{new_username}'.")
                
                # Notify admins
                admins = Users.query.filter(Users.role.in_(['operator_admin', 'manager'])).all()
                for admin in admins:
                    notification = Notification(
                        user_id=admin.id,
                        message=f"User '{old_username}' changed their username to '{new_username}'.",
                        notification_type='password_reset' # Re-using for general security alerts
                    )
                    db.session.add(notification)
                flash('Username updated successfully.', 'success')

        # --- Handle Password Change ---
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password:
            if not check_password_hash(current_user.password, current_password):
                flash('Your current password was incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            elif len(new_password) < 6:
                flash('New password must be at least 6 characters long.', 'danger')
            else:
                current_user.password = generate_password_hash(new_password)
                log_activity("Changed own password.")
                
                # Notify admins
                admins = Users.query.filter(Users.role.in_(['operator_admin', 'manager'])).all()
                for admin in admins:
                    notification = Notification(
                        user_id=admin.id,
                        message=f"User '{current_user.username}' has changed their password.",
                        notification_type='password_reset' # Re-using for general security alerts
                    )
                    db.session.add(notification)
                flash('Password updated successfully.', 'success')

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('profile.html', current_page='profile')

@app.route('/profile_image/<path:filename>')
def serve_profile_image(filename):
    """Serve profile images from any of the known upload folders."""
    search_paths = [
        os.path.join('static', filename),  # If filename already contains a folder
        os.path.join('static', 'profile_pics', filename),
        os.path.join('static', 'profileuploads', filename),
    ]

    for path in search_paths:
        if os.path.exists(path):
            return send_file(path, mimetype='image/png')

    # Fallback to placeholder
    return send_file(os.path.join('static', 'default.png'), mimetype='image/png')

@app.route('/supervisor_schedule')
@login_required
def supervisor_schedule():
    """Renders a page showing the full weekly schedule for all supervisors."""
    schedules = SupervisorSchedule.query.options(
        joinedload(SupervisorSchedule.supervisor)
    ).order_by(
        case(
            (SupervisorSchedule.day_of_week == 'Monday', 1),
            (SupervisorSchedule.day_of_week == 'Tuesday', 2),
            (SupervisorSchedule.day_of_week == 'Wednesday', 3),
            (SupervisorSchedule.day_of_week == 'Thursday', 4),
            (SupervisorSchedule.day_of_week == 'Friday', 5),
            (SupervisorSchedule.day_of_week == 'Saturday', 6),
            (SupervisorSchedule.day_of_week == 'Sunday', 7),
            else_=8
        ),
        SupervisorSchedule.start_time
    ).all()
    
    return render_template(
        'supervisor_schedule.html',
        schedules=schedules,
        current_page='supervisor_schedule'
    )

@app.route('/api/supervisor_schedule')
@login_required
def api_supervisor_schedule():
    """Provides supervisor schedule data as JSON for modal."""
    schedules = SupervisorSchedule.query.options(
        joinedload(SupervisorSchedule.supervisor).joinedload(Supervisor.subjects)
    ).order_by(
        case(
            (SupervisorSchedule.day_of_week == 'Monday', 1),
            (SupervisorSchedule.day_of_week == 'Tuesday', 2),
            (SupervisorSchedule.day_of_week == 'Wednesday', 3),
            (SupervisorSchedule.day_of_week == 'Thursday', 4),
            (SupervisorSchedule.day_of_week == 'Friday', 5),
            (SupervisorSchedule.day_of_week == 'Saturday', 6),
            (SupervisorSchedule.day_of_week == 'Sunday', 7),
            else_=8
        ),
        SupervisorSchedule.start_time
    ).all()

    results = []
    for schedule in schedules:
        results.append({
            'day': schedule.day_of_week,
            'time': f"{schedule.start_time.strftime('%I:%M %p')} - {schedule.end_time.strftime('%I:%M %p')}",
            'supervisor_name': schedule.supervisor.name,
            'supervisor_pic': url_for('serve_profile_image', filename=schedule.supervisor.profile_picture or 'default.png'),
            'subjects': ', '.join([s.name for s in schedule.supervisor.subjects]) or 'None'
        })
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)