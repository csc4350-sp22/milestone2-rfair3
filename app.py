import requests
import os
import random
import base64

from flask import Flask, render_template, url_for
from wikipedia import get_wiki_link
from tmdb import get_movie_data


app = Flask(__name__)


MOVIE_IDS = [
    10426, 
    12153, 
    584, 
    5174, 
    16555
]


@app.route("/login")
def login():
    return render_template("login.html")
    

@app.route("/register")
def register():
    return render_template("register.html")
    
@app.route("/home")
def home():
    return render_template("home.html")
    


@app.route("/")
def index():
    movie_id = random.choice(MOVIE_IDS)

    # API calls
    (title, tagline, genre, poster_image) = get_movie_data(movie_id)
    wikipedia_url = get_wiki_link(title)

    return render_template(
        "index.html",
        title=title,
        tagline=tagline,
        genre=genre,
        poster_image=poster_image,
        wiki_url=wikipedia_url,
    )




if __name__ == "__main__":
    app.run(
        host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)), debug=True
    )
