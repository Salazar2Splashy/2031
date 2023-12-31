from datetime import datetime

import bcrypt

from app import db, app
from flask_login import UserMixin
import pyotp


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    dob = db.Column(db.String(10), nullable=False)
    postcode = db.Column(db.String(7), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.now())
    current_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    logins = db.Column(db.Integer, nullable=False)

    # Define the relationship to Draw
    draws = db.relationship('Draw')
    pin_key = db.Column(db.String(32), nullable=False, default=pyotp.random_base32())

    def __init__(self, email, firstname, lastname, phone, password, role, dob, postcode):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        self.dob = dob
        self.postcode = postcode
        self.registered_on = datetime.now()
        self.last_login = None
        self.current_login = None
        self.logins = 0

    def get_2fa_uri(self):
        return str(pyotp.totp.TOTP(self.pin_key).provisioning_uri(
            name=self.email,
            issuer_name='CSC2031 Blog Arbitrary Name')
        )

    def verify_pin(self, pin):
        return pyotp.TOTP(self.pin_key).verify(pin)

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

    def verify_postcode(self, postcode):
        return self.postcode == postcode


class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self, user_id, numbers, master_draw, lottery_round):
        self.user_id = user_id
        self.numbers = numbers
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round


def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin',
                     dob="01/01/2000",
                     postcode="NE6 5SU",
                     )

        db.session.add(admin)
        db.session.commit()
