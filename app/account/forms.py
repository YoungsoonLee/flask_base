from flask import url_for
from flask_wtf import FlaskForm
from wtforms import ValidationError
from wtforms.fields import (BooleanField, PasswordField, StringField,
                            SubmitField)
from wtforms.fields.html5 import EmailField
from wtforms.validators import Email, EqualTo, InputRequired, Length, Regexp

# from ..models import User

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')


class RegistrationForm(FlaskForm):
    nickname = StringField('Nick name', validators=[
        InputRequired(), 
        Length(5, 20),
        Regexp('^\w+$', message="Nickname must contain only letters numbers or underscore"),
        ])
    # first_name = StringField('First name', validators=[InputRequired(), Length(1, 64)])
    # last_name = StringField('Last name', validators=[InputRequired(), Length(1, 64)])
    """
    email = StringField('Email', validators=[
        InputRequired(), 
        Length(1, 64), 
        Regexp("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum)\b", message="You should input email")])
        """
    email = EmailField('Email', validators=[InputRequired(), Length(1, 64), Email()])
    password = PasswordField(
        'Password',
        validators=[
            InputRequired(), EqualTo('password2', 'Passwords must match'), Length(5, 32)
        ]
        )
    password2 = PasswordField('Confirm password', validators=[InputRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        pass
        """
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered. (Did you mean to '
                                  '<a href="{}">log in</a> instead?)'
                                  .format(url_for('account.login')))
        """


class RequestResetPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Length(1, 64), Email()])
    submit = SubmitField('Reset password')

    # We don't validate the email address so we don't confirm to attackers
    # that an account with the given email exists.


class ResetPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Length(1, 64), Email()])
    new_password = PasswordField(
        'New password',
        validators=[
            InputRequired(), EqualTo('new_password2', 'Passwords must match.')
        ])
    new_password2 = PasswordField('Confirm new password', validators=[InputRequired()])
    submit = SubmitField('Reset password')

    def validate_email(self, field):
        pass
        """
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')
        """


class CreatePasswordForm(FlaskForm):
    password = PasswordField(
        'Password',
        validators=[
            InputRequired(), EqualTo('password2', 'Passwords must match.')
        ])
    password2 = PasswordField('Confirm new password', validators=[InputRequired()])
    submit = SubmitField('Set password')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old password', validators=[InputRequired()])
    new_password = PasswordField(
        'New password',
        validators=[
            InputRequired(), EqualTo('new_password2', 'Passwords must match.')
        ])
    new_password2 = PasswordField('Confirm new password', validators=[InputRequired()])
    submit = SubmitField('Update password')


class ChangeEmailForm(FlaskForm):
    change_email = EmailField('New email', validators=[InputRequired(), Length(1, 64), Email()])
    changeEmailPassword = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Update email')

    """
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
    """