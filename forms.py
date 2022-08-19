from ast import Pass    
from flask import session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, EmailField, ValidationError, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_login import current_user
from run import User_flask, db

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                            validators=[DataRequired(), Length(min=2, max=20)])
    user_fullname = StringField('Full Name',
                            validators=[DataRequired(), Length(max=100)])
    email = EmailField('Email', 
                            validators=[DataRequired(), Email()])
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Field must be equal to Confirm Password')])
    confirm_password = PasswordField('Confirm Password',
                                    validators=[DataRequired(), EqualTo('password_hash', message='Field must be equal to Password')])
    #session = session['username']
    user_group = SelectField(u'Role', choices=[('Admin', 'Admin'), ('User', 'User')], validators=[DataRequired()])
    #user_enable = SelectField(u'Is Active', choices=[('Active', 'Active'), ('Inactive', 'Inactive')], default='Active', validators=[DataRequired()])
    submit = SubmitField('Create User')

class LoginForm(FlaskForm):
    username = StringField('Username',
                            validators=[DataRequired(), Length(min=2, max=20)])
    password_hash = PasswordField('Password', validators=[DataRequired()])
    session_user = HiddenField('Session')
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateForm(FlaskForm):
    username = StringField('Username',
                            validators=[DataRequired(), Length(min=2, max=20)])
    user_fullname = StringField('Full Name',
                            validators=[DataRequired(), Length(max=100)])
    email = EmailField('Email', 
                            validators=[DataRequired(), Email()])
    #session = session['username']
    user_group = SelectField(u'Role', choices=[('Admin', 'Admin'), ('User', 'User')], validators=[DataRequired()])
    user_enable = SelectField(u'Is active', choices=[('Active', 'Active'), ('Inactive', 'Inactive')], default='Active', validators=[DataRequired()])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if current_user.user_group == 'User':    
            if username.data != current_user.username:
                user = db.session.query(User_flask).filter_by(username=username.data).first()
                if user:
                    raise ValidationError('Username Already Exist')
                return user
    
    def validate_email(self, email):
        if current_user.user_group == 'User':
            if email.data != current_user.email:
                eml = db.session.query(User_flask).filter_by(email=email.data).first()
                if eml:
                    raise ValidationError('Email Already Exist')
                return eml

class ChangePassword(FlaskForm):
    username = StringField('Username',
                            validators=[DataRequired(), Length(min=2, max=20)])
    password_hash = PasswordField('New Password', validators=[DataRequired(), EqualTo('confirm_password', message='Field must be equal to Confirm Password')])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password_hash', message='Field must be equal to Password')])
    submit = SubmitField('Save')

