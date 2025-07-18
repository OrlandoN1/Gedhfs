from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import enum

db = SQLAlchemy()

class UserRole(enum.Enum):
    VIEWER = 'Visualizador'
    UPLOADER = 'Uploader'
    ADMIN = 'Administrador'

# NOVO: Enum para o status de aprovação do usuário
class ApprovalStatus(enum.Enum):
    PENDING = 'Pendente'
    APPROVED = 'Aprovado'
    REJECTED = 'Rejeitado'

class Department(db.Model):
    __tablename__ = 'department'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    documents = db.relationship('Document', backref='department', lazy='dynamic')

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # NOVO CAMPO: Status de aprovação
    approval_status = db.Column(db.Enum(ApprovalStatus), default=ApprovalStatus.PENDING, nullable=False)
    
    departments = db.relationship('Department', secondary='user_departments', lazy='subquery',
        backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

user_departments = db.Table('user_departments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('department_id', db.Integer, db.ForeignKey('department.id'), primary_key=True)
)

class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    doc_type = db.Column(db.String(3), nullable=False)
    doc_number = db.Column(db.Integer, nullable=False)
    doc_revision = db.Column(db.Integer, nullable=False)
    revision_date = db.Column(db.Date, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    previous_version_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True)
    previous_version = db.relationship('Document', remote_side=[id], backref='next_versions')

class Bulletin(db.Model):
    __tablename__ = 'bulletin'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    expiration_date = db.Column(db.Date, nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='bulletins')
