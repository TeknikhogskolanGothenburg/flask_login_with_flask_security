from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import UserMixin, current_user, login_required
from flask_security import RoleMixin, SQLAlchemyUserDatastore, Security, roles_accepted, roles_required
from flask_security.utils import hash_password, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email
import config

app = Flask(__name__)

app.config.from_object(config)

db = SQLAlchemy(app)

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
    )

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.VARCHAR(255))
    active = db.Column(db.Boolean)
    confirmed_at = db.Column(db.DateTime)
    roles = db.relationship('Role',
                    secondary=roles_users,
                    backref=db.backref('users', lazy='dynamic')
            )

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40))
    description = db.Column(db.String(255))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email Address', validators=[InputRequired(), Email(message='Invalid email'), Length(min=2, max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])
    remember = BooleanField('Remeber me')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        user_datastore.create_user(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            username=form.username.data,
            password=hash_password(form.password.data)
        )
        db.session.commit()
        return redirect(url_for('signin'))
    return render_template('signup.html', form=form)



@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = LoginForm()
    if form.validate_on_submit():
        user = user_datastore.find_user(username=form.username.data)

        if user:
            login_user(user, remember=form.remember.data)
            return redirect(url_for('profile'))
    return render_template('signin.html', form=form)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)


@app.route('/admin')
@roles_required('admin')
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route("/signout")
def signout():
    logout_user()
    return render_template('index.html')


@app.route('/error')
def error():
    return render_template('error.html')

if __name__ == '__main__':
    app.run()
