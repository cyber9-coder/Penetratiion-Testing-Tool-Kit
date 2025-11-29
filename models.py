from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    theme = db.Column(db.String(20), default='light', nullable=False)  # 'light' or 'dark'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Security scanning results could be linked here
    scan_results = db.relationship('ScanResult', backref='user', lazy='dynamic')
    
    @staticmethod
    def create(username, email, password):
        """Create a new user with the provided details"""
        user = User()
        user.username = username
        user.email = email.lower()
        user.password_hash = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
        return user
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def update_theme(self, theme):
        """Update the user's theme preference"""
        if theme in ['light', 'dark']:
            self.theme = theme
            db.session.commit()
            return True
        return False
    
    @staticmethod
    def get(user_id):
        """Retrieve a user by ID"""
        return User.query.get(int(user_id))
    
    @staticmethod
    def find_by_email(email):
        """Find a user by email"""
        return User.query.filter_by(email=email.lower()).first()
    
    @staticmethod
    def find_by_username(username):
        """Find a user by username"""
        return User.query.filter_by(username=username).first()
    
    def __repr__(self):
        return f'<User {self.username}>'


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tool_name = db.Column(db.String(64), nullable=False)
    target = db.Column(db.String(256), nullable=False)
    result_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def create(user_id, tool_name, target, result_data):
        """Create a new scan result entry"""
        result = ScanResult()
        result.user_id = user_id
        result.tool_name = tool_name
        result.target = target
        result.result_data = result_data
        db.session.add(result)
        db.session.commit()
        return result
    
    def __repr__(self):
        return f'<ScanResult {self.tool_name} - {self.target}>'