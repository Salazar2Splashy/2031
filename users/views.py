# IMPORTS
import logging
from datetime import datetime

from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, LoginForm, PasswordForm
from flask_login import login_user, logout_user, login_required, current_user

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

        logging.warning('SECURITY - User registration [%s, %s]', form.email.data, request.remote_addr)

        session["email"] = new_user.email
        session['authentication_attempts'] = 0
        # sends user to login page
        return redirect(url_for('users.setup_2fa'))
    else:
        flash_errors(form)

    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST', ])
def login():
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first();
        if not user or not user.verify_password(form.password.data) or not user.verify_pin(
                form.pin.data) or not user.verify_postcode(form.postcode.data):
            logging.warning('SECURITY - Invalid log in attempt [%s, %s]',
                            form.email.data,
                            request.remote_addr
                            )
            session['authentication_attempts'] += 1
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded. Please click <a href = "/reset" > here < / '
                             'a > to reset.'))
                return render_template('users/login.html')
            flash('Email address, password or pin is incorrect. {} login attempts remaining'.format(
                3 - session.get('authentication_attempts')), 'error')
            return render_template('users/login.html', form=form)
        login_user(user)
        current_user.last_login = current_user.current_login
        current_user.current_login = datetime.now()
        session['authentication_attempts'] = 0
        db.session.commit()
        logging.warning('SECURITY - Log in [%s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr
                        )
        current_user.logins = current_user.logins + 1
        if current_user.role == "admin":
            return redirect(url_for('admin/admin'))

        else:
            return redirect(url_for('lottery.lottery'))
    else:
        flash_errors(form)
    # if request method is GET or form not valid re-render signup page
    return render_template('users/login.html', form=form)


@users_blueprint.route('/setup_2fa')
def setup_2fa():
    if 'email' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('index'))
    del session['email']
    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri())


@users_blueprint.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    form = PasswordForm()

    if form.validate_on_submit():

        if not current_user or not current_user.verify_password(form.current_password.data):
            flash('Incorrect current password', 'error')
            return render_template('users/update_password.html', form=form)

        current_user.password = form.new_password.data
        db.session.commit()
        flash('Password changed successfully')

        return redirect(url_for('users.account'))

    return render_template('users/update_password.html', form=form)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone,
                           role=current_user.role,
                           dob=current_user.dob,
                           postcode=current_user.postcode)


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


@users_blueprint.route('/logout')
@login_required
def logout():
    logging.warning('SECURITY - Log out [%s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    request.remote_addr
                    )
    logout_user()
    return redirect(url_for('index'))
