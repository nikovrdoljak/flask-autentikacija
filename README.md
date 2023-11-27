# Flask autentikacija - radionica

## Postavimo aplikaciju
Stvorimo radnu mapu, te u njoj postavimo i aktivirajmo virtualnu okolinu:
```
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Instalirajmo Flask:
```
pip install flask
```

Kreirajmo app.py datoteku i postavimo inicijalnu Flask aplikaciju:
```python
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Moja aplikacija</h1>'
```

Postavimo još FLASK_DEBUG varijablu na 1, te pokrenimo aplikaciju da budemo sigurni da radi:
```
$env:FLASK_DEBUG=1
flask run
```
Provjerite u pregledniku da na adresi http://localhost:5000/ web stranica prikazuje naslov "**Moja aplikacija**".

## Postavljanje Bootstrapa
Za rad s Bootstrap okvirom koristit ćemo flask_bootstrap komponentu. Dokumentaciju za nju možete pronaći na adresi https://bootstrap-flask.readthedocs.io/en/latest/.
Najprije ju instalirajmo:
```
pip install bootstrap-flask
```
U ```app.py``` datoteku dodajmo slijedeće import izraze te aktivirajmo Bootstrap objekt u aplikaciji:
``` python
from flask import Flask, render_template
from flask_bootstrap import Bootstrap5
app = Flask(__name__)
app.config['SECRET_KEY'] = 'blablastring'
bootstrap = Bootstrap5(app)
```
Dodat ćemo i prvi predložak za naslovnu stranicu, koji će naslijeđivati osnovnu Bootstrap stranicu. 
Kreirajmo mapu ```templates``` te u nju dodajmo dvije datoteke:

*base.html*
```html
{% from 'bootstrap5/nav.html' import render_nav_item %}
<!doctype html>
<html lang="en">
    <head>
        {% block head %}
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        {% block styles %}
            {{ bootstrap.load_css() }}
        {% endblock %}

        <title>Moja aplikacija</title>
        {% endblock %}
    </head>
    <body>
        <div class="container">
            <nav class="navbar navbar-expand-lg navbar-light bg-light">
                <a class="navbar-brand" href="{{url_for('index')}}">Moja aplikacija</a>
                <div class="navbar-nav mr-auto">
                    {{ render_nav_item('index', 'Početna') }}
                </div>
            </nav>
        </div>
        <div class="container">
        {% block content %}{% endblock %}
        </div>
        {% block scripts %}
            {{ bootstrap.load_js() }}
        {% endblock %}
    </body>
</html>
```

*index.html*
```html
{% extends "base.html" %}
{% block content %}
<h1>Početna stranica</h1>
{% endblock %}
```

Prmijenimo i vršnu rutu tako da iscrta ```index.html``` predložak.:
*app.py*
``` python
@app.route('/')
def index():
    return render_template('index.html')
```

Ako ste sve točno postavili i ponovo pokrenuli aplikaciju trebali biste dobiti slijedeći izgled stranice:
![Bootstrap stranica](/assets/c1-bootstrap.png)

Primijetite da koristimo Boostrap 5, te da smo u baznoj stranicu iskoristili macro ```render_nav_item``` za stvaranje elementa menija u zaglavlju stranice. Također ```index.html``` predložak naslijeđuje bazni ```base.html``` predložak preko definicije:

```{% extends "base.html" %}```

# Autentikacija

* Proces u kojem ustanovljavamo tko ili što jest ili se deklarira da je.
* Odvija se na način da uspoređujemo vjerodajnice (credentials) korisnika sa vjerodajnicama spremljenim u bazi autentikacijskog poslužitelja.
* Autentikacija je bitna jer omogućava da određenim resursima smiju pristupiti samo ovlašteni korisnici ili procesi .

## Faktori autentikacije
* **Faktor znanja** – ono što korisnik zna – zaporka, fraza, PIN, odgovor na pitanje
* **Faktor vlasništva** – ono što korisnik ima – kartica, narukvica, telefon…
* **Faktor pripadnosti** – ono što korisnik jest ili radi – otisak prsta, mrežnica, glas, lice, potpis…
* **Faktor vremena**
* **Faktor lokacije**

Da bi se osoba pozitivno autenticirala, poželjno je da elementi barem dva faktora budu verificirani.

## Tipovi autentikacije
* Single-factor
    * Provjera autentičnosti s jednim faktorom
    * Najslabija i nepoželjna za transakcije koje traže visok nivo zaštite
* Two-factor
    * Bankomat – nešto što korisnik ima (kartica) i zna (PIN)
    * Ili zaporka (znamo) + token (imamo; na uređaju)
* Multi-factor

## Autentikacija u flasku
* Korisnički ime ili email + zaporka
* Flask-login
    * Ekstenzija za upravljanje sesijama prijavljenih korisnika
    * ```pip install flask-login```
* Forma za prijavu
    * LoginForm
    * ```pip install flask-wtf``` (imamo od ranije u projektu)

## Zaštita zaporke
Zaporka se nikad ne smije spremati u izvornom obliku, te se sprema njen *hash*.
Hashing funkcija uzima zaporku kao ulazni argument, dodaje slučajnu sekvencu (*salt*) i primjenjuje jednosmjernu kriptografsku funkciju. Rezultat je sekvenca iz koje se ne može reverzno dobiti izvornu zaporku. Zatim uspoređujemo *hashiranu* zaporku koju je korisnik upisao s onom u bazi. Detaljnije o ovoj temi možete pronaći na linku: [Salted Password Hashing - Doing it Right](https://crackstation.net/hashing-security.htm)

### Generiranje i provjera hash-a
```python
flask shell
>>> from werkzeug.security import generate_password_hash, check_password_hash
>>> hash1 = generate_password_hash('123')
>>> print(hash1)
pbkdf2:sha256:50000$ClVWrTj0$d9ef0819c7bcd9ac996079d284f87f4969f3ba09e504c58a839a169ef10c7193
>>> check_password_hash(hash1, '123')
True
```

### Forma za prijavu
Dodat ćemo sad formu za logiranje te pripadnu programsku logiku uz pomoć [flask-login](https://flask-login.readthedocs.io/en/latest/) ekstenzije. Dodajmo najprije klasu za *login* formu u ```app.py```:
```python
class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Zaporka', validators=[DataRequired()])
    remember_me = BooleanField('Ostani prijavljen')
    submit = SubmitField('Prijava')
```
te uvezimo dodatne potrebne module:
```python
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Length, InputRequired, DataRequired, Email, EqualTo
from flask_wtf import FlaskForm

```
Email validator je potrebno zasebno instalirati:
```
pip install email-validator
```
Dodajmo rutu:
```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    return render_template('login.html', form = form)
```
i predložak ```login.html```
```jinja
{% extends "base.html" %}
{% from 'bootstrap5/form.html' import render_form %}

{% block title %}Prijava{% endblock %}

{% block content %}
<div class="container">
    <div class="page-header">
        <h1>Prijava</h1>
    </div>
    <div class="col-md-4">
        {{ render_form(form) }}
    </div>
</div>
{% endblock %}
```
U ```base.html``` dodajmo link za prijavu:
```html
<div class="navbar-nav mr-auto">
    {{ render_nav_item('login', 'Prijava') }}
</div>
```
Da bismo mogli jednostavnije raditi s prijavom, koristit ćemo [flask-login](https://flask-login.readthedocs.io/en/latest/) ekstenziju. Instalirajmo je:
```
pip install flask-login
```
Flask-login ekstenzija s brine o prijavi, odjavi i pamćenju korisnikove sesije tijekom vremena. Ona radi slijedeće:
* Pamti korisnički ID u sesiji i brine se o prijavi i odjavi
* Omogućava da označite koje *view-ove* može samo prijavljeni korisnik vidjeti
* Brine o implementaciji *"zapamti me"* funkcionalnosti
* Omogućava da netko ne može *ukrasti* korisničku sesiju
* Lako se integrira s drugim ekstenzijama poput *flask-principal* za autorizaciju

Ono što moramo sami napraviti je:
* Pobrinuti se gdje ćemo spremati podatke (u bazu npr.)
* Odlučiti koju metodu autentikacije ćemo koristiti (korisnik/zaporka, OpenID, i sl.)
* Brinuti o načinu registracije, obnovi zaporke i sl.

Dodajmo potrebne module:
```python
from flask_login import UserMixin
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
```
Konfigurirajmo aplikaciju da koristi flask-login:
```python
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
```
I promijenimo ```User``` klasu da naslijeđuje i tzv. ```UserMixin``` klasu:
```python
class User(UserMixin):
    USERS = {
        'jure@unizd.hr': 'sifra1',
        'ana@unizd.hr': 'sifra2',
        'ivana@unizd.hr': 'sifra3'
    }

    def __init__(self, id):
        with open('users.json') as datoteka:
            self.USERS = json.load(datoteka)
            datoteka.close()

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
```

Dodajmo login rutu (za sad nećemo provjeravati zaporku):
```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            flash('Uspješno ste se prijavili!', category='success')
            return redirect(next)
        flash('Neispravno korisničko ime ili zaporka!', category='warning')
    return render_template('login.html', form=form)
```
Dodajmo i 
```python
from flask import request, flash
```
Te na kraju dodajmo u ```index.html```:
```html
<div class="mt-4">
    <h4>current_user:</h4>
    <p>username: <b>{{current_user.username}}</b></p>
    <p>is_authenticated: <b>{{current_user.is_authenticated}}</b></p>
    <p>is_active: <b>{{current_user.is_active}}</b></p>
    <p>is_anonymous: <b>{{current_user.is_anonymous}}</b></p>
    <p>get_id(): <b>{{current_user.get_id()}}</b></p>
</div>
```
Te još jednu rutu, kojoj smije pristupiti samo autenticirani korisnik:
```python
@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')
```

te ```seceet.html``` view:
```html
{% extends "base.html" %}
{% block content %}
<p>Ovu stranicu može vidjeti samo prijavljeni korisnik.</p>
{% endblock %}
```

U ```base.html``` dodajmo link za ovu rutu:
```html
<div class="navbar-nav mr-auto">
    {{ render_nav_item('secret', 'Secret') }}
</div>
```

### Odjava
Dodajmo sad i fukcionalnost odjave. Promijenimo u ```base.html``` link za prijavu:
```html
    {% if current_user.is_authenticated %}
    <div class="navbar-nav mr-auto">
        {{ render_nav_item('logout', 'Odjava') }}
    </div>
    {% else %}
    <div class="navbar-nav mr-auto">
        {{ render_nav_item('login', 'Prijava') }}
    </div>
    {% endif %}
```
Dodajmo rutu za odjavu:
```python
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Odjavili ste se.', category='success')
    return redirect(url_for('index'))
```

Dodajmo i podršku za "flash" poruke u ``base.html``` odhmah ispod "container" elementa:
```html
    {% with messages = get_flashed_messages() %}
    {% if messages %}
        {% for message in messages %}
        <div class="alert alert-primary" role="alert">{{ message }}</div>
        {% endfor %}
    {% endif %}
    {% endwith %}
```

### Registracija
Sad ćemo dodati funkcionalnost registracije. Dodajmo rutu i klasu forme:
```python
from wtforms.validators import EqualTo

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
```
I dodajmo ```register.html``` predložak:
```jinja
{% extends "base.html" %}
{% from 'bootstrap5/form.html' import render_form %}

{% block title %}Registracija{% endblock %}

{% block content %}
<div class="container">
    <div class="page-header">
        <h1>Registracija</h1>
    </div>
    <div class="col-md-4">
        {{ render_form(form) }}
    </div>
</div>
{% endblock %}
```
U ```login.html``` dodajmo gumb za registraciju ispod forme za prijavu:
```html
    <div class="col-md-12" class="mt-4">
        Novi korisnik?<br> <a href="{{url_for('register')}}" class="btn btn-warning">Registrirajte se</a>
    </div>
```

U User klasu dodajmo add metodu:
```Python
    @staticmethod
    def add(id, password):
        entries = {}
        with open('users.json', mode='r') as datoteka:
            entries = json.load(datoteka)
            datoteka.close()
        entries[id] = generate_password_hash(password)
        with open('users.json', mode='w') as datoteka:
            json.dump(entries, datoteka)
```

A u ```def __init__``` metodu dodajmo da se korisnici učitavaju iz Json datoteke koju ćemo staviti u datoteku ```users.json``` mapu aplikacije, a izbrisati iz koda:
```Python
        with open('users.json') as datoteka:
            self.USERS = json.load(datoteka)
            datoteka.close()
```

```Json
{
  "jure@unizd.hr": "sifra1",
  "ana@unizd.hr": "sifra2",
  "ivana@unizd.hr": "sifra3"
}
```
Dodajmo i:
```python
import json
from werkzeug.security import generate_password_hash
```

### Potvrda registracije
Ovdje ćemo samo pokazati kako bi trebao izgledati proces potvrde registracije. Naime jedan od obaveznih koraka pri registraciji je potvrda iste mailom, gdje korisnik mora kliknuti aktivacijski link.
Taj link mora imati korisničko ime kriptirano, stoga moramo napraviti otprilike slijedeće:
```python
flask shell
>>> from itsdangerous import TimedJSONWebSignatureSerializer as serializer
>>> s = serializer(app.config['SECRET_KEY'], expires_in=3600)
>>> token = s.dumps({ 'potvrdi': 'nvrdoljak@unizd.hr' })
>>> token
b'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU0MzkyMTE4NiwiZXhwIjoxNTQzOTI0Nzg2fQ.eyJwb3R2cmRpIjoibWFyaW9AdW5pemQuaHIifQ.tFRcBO0gjDzDcD4AL0eRx453ULdaq07MKWE6y-Nt8MnL3tesH7_VbFIFlcZSE2AxB1EdC3jbRdxSQ3o4JwDX_w'
>>> data = s.loads(token)
>>> data
{'potvrdi': 'nvrdoljak@unizd.hr'}
```
Sadržaj emaila može biti npr. ovakav:
```python
Poštovani {{ user.username }},
Da biste potvrdili svoju prijavu, molimo kliknite na slijedeći link:
{{ url_for('confirm', token=token, _external=True) }}
Srdačan pozdrav.
```
A pripadna ruta bi izgledala ovako:
```python
@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('Vaša prijava je potvrđena! Hvala.')
    else:
        flash('Link za potvrdu je neispravan ili je istekao.')
    return redirect(url_for('index'))
```

## Ostali scenariji
* Promjena passworda
* Resetiranje passworda
* Promjena email adrese

## Slijedeće
Autorizacija i korištenje ```flask-principal``` ekstenzije.
