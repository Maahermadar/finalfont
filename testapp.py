from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# 🔧 Basic Flask app setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:0099..@localhost:5432/font_database'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🔗 Initialize database
db = SQLAlchemy(app)

# 📦 Define a simple Editor model
class testifu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)

# ✅ Create table and test connection
with app.app_context():
    try:
        # Test connection
        db.session.execute(text("SELECT 1"))
        print("✅ Connected to database successfully.")

        # Create the table
        db.create_all()
        print("✅ Table 'editor' created successfully.")

    except Exception as e:
        print(f"❌ Failed to connect or create table: {e}")
