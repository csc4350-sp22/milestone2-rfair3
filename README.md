# Milestone2-rfair3

Link to Heroku: https://peaceful-depths-02160.herokuapp.com/ 

For anyone looking to clone my repository and run the app locally: 

You will need to install the following using pip or pip3 install: 

Flask

requests

flask-login

Flask-WTf

Flask

SQLAlchemy

WTForms

Flaks-bcrypt

dotenv

psycopg2

You also need to reqister for 3 things. The first is a api key from The Movie Database.
The API key that you will need is version 3. The second is register for a heroku database 
using the command "heroku create" and "heroku addons:create heroku-postgresql:hobby-dev"
in your terminal. IF THE URL STARTS WITH postgres:, replace that with postgresql:
Finally you will also need t ocreate a secrect key of your choice. This can be any 
combination of characters. Your .env file should look like the following:

export api_key= “YOUR API KEY HERE”
export DATABASE_URL="YOUR DATABASE KEY HERE"
export SECRET_KEY="YOUR SECRET KEY HERE"

Make sure to also add the .env file to a .gitignore file. To run the app locally, in your
terminal run "python app.py". This is all of the requirements to get the app up and running locally.


A technical issue that arose during the building process was getting the database to import from 
VSCode to heroku app. The issue was that in Heroku, the URL was changed to postgres and needed to be 
postgresql. This menas that any time i tried to submit a form, the app would crash. To fix this, 
i had to use a start with and replace call which fixed the issue. This information came from one of my
classmates in the class discord who expierenced the same problem. Another issue that arrose is that I was trying 
to use return render_templates that made the app crash. This is due to having 2 return methods of the same type 
running at the same time. To fix this, I returned all of my main information in 1 return template.I got this information 
from stackoverflow and multiple youtube videos. I also rewatched lecture 8 and 9 to also work me through this issue. 


My experience working on this milestone differed greatly from what I pictured while working through
the planning process. I thought that all I had to do was import a database into the project and that this would be 
the process. I was completely wrong. You can't just import a table and think it will run. There were many issues i encountered
while trying to get my database to import to my html file. The app kept crashing and it was due to the fact that the information 
was not being passed to the index.html file. A simple fix but it took me 2 days to finally figure out what was going on with my 
code. What was unexpectedly easy was creating a username and password system on the site. This was also done using a database and 
comparing the password to what the user inputed. Overall the project taught me many valuable lessons along the way.
