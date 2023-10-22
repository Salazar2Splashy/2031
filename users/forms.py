from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, validators
from wtforms.validators import Email, ValidationError, Regexp, Length, EqualTo, DataRequired
import re


def character_check(form, field):
    excluded_characters = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_characters:
            raise ValidationError(f"Character {char} is not allowed in Name")


def password_check(form, field):
    p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^A-Za-z0-9])')
    if not p.match(field.data):
        raise ValidationError("Password must contain at least 1 special character, uppercase letter, lowercase letter and digit")


class RegisterForm(FlaskForm):
    email = StringField(validators=[Email(message="Please enter a valid e-mail address"), DataRequired(message="Field cannot be blank")])
    firstname = StringField(validators=[character_check, DataRequired(message="Field cannot be blank")])
    lastname = StringField(validators=[character_check, DataRequired(message="Field cannot be blank")])
    dob = StringField(validators=[Regexp(regex="^[0-9]{2}[/][0-9]{2}[/][0-9]{4}$"), DataRequired(message="Field cannot be blank")])
    phone = StringField(validators=[Regexp(regex="^[0-9]{4}[-][0-9]{3}[-][0-9]{4}$"), DataRequired(message="Field cannot be blank")])
    password = PasswordField(validators=[Length(min=6, max=12, message="Password must be 6-12 characters long"), password_check, DataRequired(message="Field cannot be blank")])
    confirm_password = PasswordField(validators=[EqualTo('password', message="Passwords do not match"), DataRequired(message="Field cannot be blank")])
    submit = SubmitField()
