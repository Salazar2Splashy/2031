from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, validators
from wtforms.validators import Email, ValidationError, Regexp, Length, EqualTo, DataRequired
import re
from flask_wtf import RecaptchaField


def character_check(form, field):
    excluded_characters = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_characters:
            raise ValidationError(f"Character {char} is not allowed in Name")


def password_check(form, field):
    p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^A-Za-z0-9])')
    if not p.match(field.data):
        raise ValidationError(
            "Password must contain at least 1 special character, uppercase letter, lowercase letter and digit")


def postcode_check(form, field):
    p = re.compile("^[A-Z][0-9] [0-9][A-Z]{2}$")
    p2 = re.compile("^[A-Z][0-9]{2} [0-9][A-Z]{2}$")
    p3 = re.compile("^[A-Z]{2}[0-9] [0-9][A-Z]{2}$")
    if not p.match(field.data) and not p2.match(field.data) and not p3.match(field.data):
        raise ValidationError(
            "Postcode must be in the forms XY YXX, XYY YXX or XXY YXX where X is a letter and Y is a number. Letters "
            "must be all in caps.")


class RegisterForm(FlaskForm):
    email = StringField(validators=[Email(message="Please enter a valid e-mail address"),
                                    DataRequired(message="Field cannot be blank")])
    firstname = StringField(validators=[character_check, DataRequired(message="Field cannot be blank")])
    lastname = StringField(validators=[character_check, DataRequired(message="Field cannot be blank")])
    phone = StringField(
        validators=[Regexp(regex="^[0-9]{4}[-][0-9]{3}[-][0-9]{4}$", message="Phone number must be a String containing "
                                                                             "only digits (X) and dashes (-) of the "
                                                                             "form: XXXX-XXX-XXXX "), DataRequired(
            message="Field cannot be blank")])
    dob = StringField(
        validators=[Regexp(regex="^[0-3][0-9][/][0-1][0-2][/](19|20)[0-9]{2}$", message="Must be a String containing "
                                                                                        "only"
                                                                                        "appropriate digits and "
                                                                                        "forward slashes"
                                                                                        "(/) of the form: DD/MM/YYYY "
                                                                                        "- D (Day),"
                                                                                        "M (Month), Y (Year)."),
                    DataRequired(
                        message="Field cannot be blank")])
    postcode = StringField(validators=[postcode_check, DataRequired(message="Field cannot be blank")])
    password = PasswordField(
        validators=[Length(min=6, max=12, message="Password must be 6-12 characters long"), password_check,
                    DataRequired(message="Field cannot be blank")])
    confirm_password = PasswordField(validators=[EqualTo('password', message="Passwords do not match"),
                                                 DataRequired(message="Field cannot be blank")])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField(validators=[Email(message="Please enter a valid e-mail address"),
                                    DataRequired(message="Field cannot be blank")])
    password = PasswordField(
        validators=[Length(min=6, max=12, message="Password must be 6-12 characters long"), password_check,
                    DataRequired(message="Field cannot be blank")])
    pin = StringField(
        validators=[
            DataRequired(message="Field cannot be blank")])
    recaptcha = RecaptchaField()
    submit = SubmitField()
