from datetime import datetime, timedelta, date
from sqlalchemy.exc import IntegrityError, PendingRollbackError, InternalError
from urllib import request
from flask_session import Session
from flask import Flask, render_template, url_for, flash, redirect, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Table, MetaData
from sqlalchemy.engine import reflection
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.automap import automap_base
import os
from tree import make_tree
from psycopg2.errors import UniqueViolation
from psycopg2 import errors


app = Flask(__name__)

SESSION_TYPE = 'sqlalchemy'
app.config['SECRET_KEY'] = '6456efcba334c1c00b9b6ff3fff92736'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:rahasia@localhost:6543/flaskdb'
db = SQLAlchemy(app)
SESSION_SQLALCHEMY = db
app.permanent_session_lifetime = timedelta(minutes=5)
app.config.from_object(__name__)
SESSION_SQLALCHEMY_TABLE = 'sessions'
Base = automap_base()
Base.prepare(db.engine, reflect=True)
Sessions = Base.classes.sessions

sess = Session()
sess.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in first to access this page."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return User_flask.query.get(int(user_id))


class User_flask(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    user_fullname = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_enable = db.Column(db.String(15), default='Active', nullable=False)
    user_group  = db.Column(db.String(20), nullable=False)
    session_user = db.Column(db.String(150), nullable=True)

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")
    
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password) 
    #def __init__(self, username, password, user_fullname, email, user_group, user_enable):
        #self.username=username
        #self.password=password
        #self.user_fullname=user_fullname
        #self.email=email
        #self.user_group=user_group
        #self.user_enable=user_enable
        
    def __repr__(self):
        return '<Username %r>' and self.username


@app.route("/")
@app.route("/index")
@login_required
def index():
    return render_template("index.html", title='Home')

@app.route("/admin/")
@login_required
def adminIndex():
    return render_template('admin/index.html', title='Admin Site')

@app.route("/admin/user")
@login_required
def userAdmin():
    users = User_flask.query.order_by(User_flask.create_date)
    return render_template('admin/userAdmin.html', users=users, title="Manage Users")

@app.route("/folder-structure")
@login_required
def folder_structure():
    if current_user.user_group == 'Admin':
        path = os.path.expanduser(u'~')
        return render_template("admin/folder-structure.html", tree=make_tree(path))
    else:
        path = os.path.expanduser(u'~')
        return render_template("folder-structure.html", tree=make_tree(path))

@app.route("/about")
@login_required
def about():
    users = User_flask.query.order_by(User_flask.create_date)
    if current_user.user_group == 'Admin':
        return render_template('admin/profile.html', title='About', users=users)
    else:
        return render_template('user/user.html', title='About', users=users)

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    user_delete = User_flask.query.get_or_404(id)
    users = User_flask.query.order_by(User_flask.create_date)
    try:
        db.session.delete(user_delete)
        db.session.commit()
        flash("User Deleted Successfully!", "danger")
        return render_template("admin/userAdmin.html", users=users, user_delete=user_delete)
    except:
        flash("Error! Looks like there was a problem... Try Again!", "warning")
        return render_template("admin/userAdmin.html", users=users, user_delete=user_delete)

@app.route("/user/change-password/<int:id>", methods=['GET', 'POST'])
@login_required
def userChangePassword(id):
    user_password = User_flask.query.get_or_404(id)
    form = ChangePassword()
    if form.validate_on_submit():
        username=request.form.get('username')
        user_password.password_hash = request.form.get('password_hash')
        if username == "" or user_password.password_hash == "":
            flash("Please fill the field", 'danger')
            return render_template('password.html', form=form, user_password=user_password, title="Change Password")
        else:
            users=User_flask.query.filter_by(username=username).first()
            if users:
                hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
                User_flask.query.filter_by(username=username).update(dict(password_hash=hashed_pw))
                db.session.commit()
                if current_user.user_group == 'User':
                    flash("Password Change Successfully", "success")
                    return redirect(url_for('user'))
                else:
                    flash("Password Change Successfully", "success")
                    return redirect(url_for('userAdmin'))
            else:
                flash('Invalid Username', 'danger')
                return render_template("password.html", user_password=user_password, form=form, title="Change Password") 
    else:
        return render_template("password.html", user_password=user_password, form=form, title="Change Password") 
        
    

@app.route("/update/<int:id>", methods=['GET', 'POST'])
@login_required
def update(id):
    user_update = User_flask.query.get_or_404(id)
    form = UpdateForm(obj=user_update)
    if current_user.user_group == 'Admin':
        if request.method == 'POST':
            if form.validate_on_submit():
                user_update.username = form.username.data
                user_update.user_fullname = form.user_fullname.data
                user_update.email = form.email.data
                user_update.user_enable = form.user_enable.data
                user_update.user_group = form.user_group.data

                #usr = db.session.query(User_flask).filter(User_flask.id!=user_update.id).filter(User_flask.username!=form.username.data).first()
                #eml = db.session.query(User_flask).filter(User_flask.email!=user_update.email).filter(User_flask.email!=user_update.email).first()
                #if User_flask.query.filter_by(username=form.username.data).first() and form.username.data != current_user.username:
                try:
                    db.session.merge(user_update)
                    db.session.commit()
                    flash('User Updated Successfully', 'success')
                    return redirect(url_for('userAdmin'))
                except IntegrityError:
                    db.session.rollback()    
                    flash('Username Or Email Already Exists!', "warning")
                    return render_template('admin/updateAdmin.html', title='Update User', form=form, user_update=user_update)
                finally:
                    db.session.close()
            else:
                return render_template('admin/updateAdmin.html', form=form, user_update=user_update, title='Update User')
        else:
            return render_template('admin/updateAdmin.html', form=form, user_update=user_update, title='Update User')
    else:
        if request.method == 'POST':
            if form.validate_on_submit():
                user_update.username = form.username.data
                user_update.user_fullname = form.user_fullname.data
                user_update.email = form.email.data

                try:
                    db.session.commit()
                    flash('User Updated Successfully', 'success')
                    return redirect(url_for('about'))
                except:    
                    flash('Error! Looks like there was an error!', 'warning')
                    return render_template('user/updateUser.html', title='Update User', form=form, user_update=user_update)
            else:
                return render_template('user/updateUser.html', form=form, user_update=user_update, title='Update User')
        else:
            return render_template('user/updateUser.html', form=form, user_update=user_update, title='Update User')

@app.route("/add_user", methods=['GET', 'POST'])
@login_required
def register():
    username = None
    email = None
    form = RegistrationForm()
    if form.validate_on_submit():
        usr = User_flask.query.filter_by(username=form.username.data).first()
        eml = User_flask.query.filter_by(email=form.email.data).first()
        if usr is None:
            if eml is None:
                hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
                usr = User_flask(username=form.username.data, password_hash=hashed_pw, user_fullname=form.user_fullname.data, email=form.email.data, user_group=form.user_group.data)
                db.session.add(usr)
                db.session.commit()
                
                flash(f'Account created for {form.username.data}!', 'success')
                return redirect(url_for('adminIndex'))
            else:
                flash('Email Already Exists!', 'warning')
                return render_template('add_user.html', title='Register', form=form, username=username, email=email)
        else:
            flash('Username Already Exists!', 'warning')
            return render_template('add_user.html', title='Register', form=form, username=username, email=email)
    return render_template('add_user.html', title='Register', form=form, username=username, email=email)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Been Logged Out!", "success")
    return redirect(url_for('login'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    username = None
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User_flask.query.filter_by(username=form.username.data).first()
            if user:
                # check the hash
                if check_password_hash(user.password_hash, form.password_hash.data):
                    login_user(user)
                    sesss = db.session.query(Sessions).order_by(Sessions.session_id.desc()).with_entities(Sessions.session_id).first()
                    form.session_user.data = sesss
                    print("Hello", sesss)
                    User_flask.query.filter_by(username=user.username).update(dict(session_user=str(sesss)))
                    #db.session.query(User_flask).filter_by(username=user).update({'session_user':form.session_user.data})
                    db.session.commit()
                    flash(f"Login Succesfull!! hello {form.username.data}!", "success")
                    if current_user.user_group == 'Admin':
                        return redirect(url_for('adminIndex', form=form, username=username))
                    else:
                        return redirect(url_for('index', form=form, username=username, user=user))
                else:
                    flash("Wrong Password - Try Again!", "warning")
            else:
                flash("User Doesn't Exists!", "warning")
                return redirect(url_for('login'))
    return render_template('login.html', form=form, username=username, title='Login')
    #if request.method == "POST" and 'username' in request.form and 'password' in request.form:
        #session.permanent = True
        #username = request.form["username"]
        #password = request.form["password"]
        #session["username"] = username
        #session["password"] = password
        #return redirect(url_for("home"))    
    #return render_template('login.html', title='Login', form=form, user=user)

from forms import ChangePassword, RegistrationForm, LoginForm, UpdateForm

if __name__ == "__main__":
    app.run(debug=True)