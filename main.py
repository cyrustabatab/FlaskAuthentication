from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os


login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register',methods=['GET','POST'])
def register():

    if request.method == 'POST':
        email = request.form['email']
        
        if User.query.filter_by(email=email).first():
            flash("That email is already registered. Please login.")
            return redirect(url_for('login'))

        password = request.form['password']
        hashed_password= generate_password_hash(password,method='pbkdf2:sha256',salt_length=8)
        name = request.form['name']

        user = User(email=email,password=hashed_password,name=name)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        return redirect(url_for('secrets'))

    return render_template("register.html",logged_in=current_user.is_authenticated)

@app.route('/login',methods=['GET','POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This email does not exist")
            return redirect(url_for('login'))
        else:
            if check_password_hash(user.password,password):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash("This password is incorrect")

    return render_template("login.html",logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    name = current_user.name
    return render_template("secrets.html",name=name,logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    flash('Successfully Logged Out')
    return redirect(url_for('login'))


@app.route('/download')
@login_required
def download():
    directory = os.path.join('static','files')
    filename = 'cheat_sheet.pdf'
    return send_from_directory(directory,filename)


if __name__ == "__main__":
    app.run(debug=True)
