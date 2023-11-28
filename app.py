from flask import Flask, render_template, flash, redirect, request, url_for, redirect
from flask_bootstrap import Bootstrap5
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Length, InputRequired, DataRequired, Email, EqualTo
from flask_wtf import FlaskForm
from flask_login import UserMixin
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
import json
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'blablastring'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bootstrap = Bootstrap5(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class User(UserMixin):
    USERS = {
        'jure@unizd.hr': 'sifra1',
        'ana@unizd.hr': 'sifra2',
        'ivana@unizd.hr': 'sifra3'
    }

    def __init__(self, id):
        if not id in self.USERS:
            raise UserNotFoundError()
        self.id = id
        self.password = self.USERS[id]
         
    @classmethod
    def get(self_class, id):
        try:
            return self_class(id)
        except UserNotFoundError:
            return None
        
    @staticmethod
    def add(id, password):
        entries = {}
        with open('users.json', mode='r') as datoteka:
            entries = json.load(datoteka)
            datoteka.close()
        entries[id] = generate_password_hash(password)
        with open('users.json', mode='w') as datoteka:
            json.dump(entries, datoteka)

class UserNotFoundError(Exception):
    pass

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Zaporka', validators=[DataRequired()])
    remember_me = BooleanField('Ostani prijavljen')
    submit = SubmitField('Prijava')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get(form.email.data)
        if user is not None and user.password == form.password.data:
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            flash('Uspješno ste se prijavili!', category='success')
            return redirect(next)
        flash('Neispravno korisničko ime ili zaporka!', category='warning')
    return render_template('login.html', form=form)

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Odjavili ste se.', category='success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        User.add(form.email.data, form.password.data)
        flash('Sad se možete prijaviti', category='success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
    
class RegisterForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Zaporka', validators=[DataRequired(), EqualTo('password2', message='Zaporke moraju biti jednake.')])
    password2 = PasswordField('Potvrdi zaporku', validators=[DataRequired()])
    submit = SubmitField('Registracija')
