from wsgiref.validate import validator
import requests
import os
import random
import base64

from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wikipedia import get_wiki_link
from tmdb import get_movie_data




app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#Table for username and password
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(300), nullable=False)

#Table for movie id, comments and ratings
class Comment(db.model):
    id = db.Column(db.Integer, primary_key=True)
    movid = db.Column(db.String(300), nullable=False)
    comments = db.Column(db.String(300), nullable=False)
    rating = db.Column(db.Integer(30), nullable=False)




#Allows user to register using form
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[ InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")


    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "Opps. Someone already has that username. Please choose a different one.")


#Takes username and pw and compares 
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[ InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")




MOVIE_IDS = [
    10426, 
    12153, 
    584, 
    5174, 
    16555
]

#Login Users if account exists 
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
    return render_template("login.html", form=form)
    


#Register Users 
@app.route("/register", methods=['GET', 'POST'])
def register():
    form= RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data.encode('utf-8'))
        new_user = User(username=form.username.data, password=hashed_password.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)



#Logout user after done commenting and viewing site 
@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    

#Displays movies on website 
@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    movie_id = random.choice(MOVIE_IDS)

    # API calls
    (movieid, title, tagline, genre, poster_image) = get_movie_data(movie_id)
    wikipedia_url = get_wiki_link(title)

    return render_template(
        "index.html",
        title=title,
        tagline=tagline,
        genre=genre,
        poster_image=poster_image,
        wiki_url=wikipedia_url,
        movieid=movieid,
    )



if __name__ == "__main__":
    app.run(
        host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)), debug=True
    )
