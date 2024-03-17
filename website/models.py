from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sNum = db.Column(db.String(8))
    campus = db.Column(db.String(15))
    details = db.Column(db.String(500))
    image_given = db.Column(db.String(10))
    image = db.Column(db.BLOB)
    severity = db.Column(db.String(20))
    progress= db.Column(db.String(150))
    staff= db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    position = db.Column(db.String(150))
    reports = db.relationship('Report')
    student = db.relationship('Student')
    staff = db.relationship('Staff')

class Student(db.Model):
    student_num = db.Column(db.String(150), primary_key=True)
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    
