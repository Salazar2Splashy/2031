# IMPORTS
from flask import Blueprint, render_template, flash, redirect, url_for, session
from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, LoginForm
from flask_login import login_user

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(error, 'error')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()
    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists', 'error')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        dob=form.dob.data,
                        postcode=form.postcode.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        session["email"] = new_user.email
        # sends user to login page
        return redirect(url_for('users.setup_2fa'))
    else:
        flash_errors(form)

    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login')
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first();
        if not user or not user.verify_password(form.password.data) or not user.verify_pin(form.pin.data):
            session['authentication_attempts'] += 1
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded. Please click <a href = "/reset" > here < / a > to reset.'))
                return render_template('users/login.html')
            flash('Email address, password or pin is incorrect. {} login attempts remaining'.format(3 - session.get('authentication_attempts')), 'error')
            return render_template('users/login.html', form=form)
        login_user(user)
        session['authentication_attempts'] = 0
        # sends user to index page
        return redirect(url_for('index'))
    else:
        flash_errors(form)

    # if request method is GET or form not valid re-render signup page
    return render_template('users/login.html', form=form)


@users_blueprint.route('/setup_2fa')
def setup_2fa():
    if 'email' not in session:
        return redirect(url_for('main.index'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('main.index'))
    del session['email']
    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri())


# view user account
@users_blueprint.route('/account')
def account():
    return render_template('users/account.html',
                           acc_no="PLACEHOLDER FOR USER ID",
                           email="PLACEHOLDER FOR USER EMAIL",
                           firstname="PLACEHOLDER FOR USER FIRSTNAME",
                           lastname="PLACEHOLDER FOR USER LASTNAME",
                           phone="PLACEHOLDER FOR USER PHONE"),


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))

