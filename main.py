from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, flash, get_flashed_messages, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)

app.config['SECRET_KEY'] = 'OfCourseIamGonnaTheBest'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = StringField(label='Password', validators=[DataRequired()])
    confirm_password = StringField(label='Re-enter Password', validators=[DataRequired()])
    name = StringField(label='Name', validators=[DataRequired()])
    submit = SubmitField(label='Register')

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = StringField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Log In')


@login_manager.user_loader
def load_user(user_id):
    #return User.query.get(int(user_id))
    return db.session.get(User, int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


#Register route
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    loginform = LoginForm()
    if request.method == "POST":
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            print("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        if form.password.data != form.confirm_password.data:
            print("Passwords don't match, please try again.")
            flash("Passwords don't match, please try again.")
            return render_template('register.html', form=form)
        
        print("Success")
        new_user = User(
            email=form.email.data,
            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        if current_user.is_authenticated:
            flash("You have successfully registered!")
        return redirect(url_for('secrets'))
    return render_template("register.html", form=form)


#Login route
@app.route('/login', methods=["GET", "POST"])
def login():
    if 'pw_count' not in session:
        session['pw_count'] = 3

    form = LoginForm()
    if request.method == "POST":
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist, please register or try again.")
            return render_template('login.html', form=form)
        elif not check_password_hash(user.password, password):
            session['pw_count'] -= 1
            flash(f"Password incorrect, please try again. You have {session['pw_count']} more tries left.")
            if session['pw_count'] <= 0:
                print("You've entered the wrong password 3 times, you are being redirected to registration page.")
                flash("You've entered the wrong password 3 times, you are being redirected to registration page.")
                session.pop('pw_count', None)  # Reset count after 3 failed attempts
                return redirect(url_for('register'))
            return render_template('login.html', form=form, pw_count=session['pw_count'])
        else:
            login_user(user)
            session.pop('pw_count', None)  # Reset count on successful login
            flash("You have successfully logged in!")
            return redirect(url_for('secrets'))
    return render_template("login.html", form=form, pw_count=session['pw_count'])



#Secrets route
@app.route('/secrets', methods=["GET", "POST"])
@login_required
def secrets():
    username = current_user.name
    if username == None:
        print("You need to log in first!")
        return redirect(url_for('login'))
    return render_template("secrets.html", name=username)


#logout route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

#Download file route
@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory('static/files', filename, as_attachment=True)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
