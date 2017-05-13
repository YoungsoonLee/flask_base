from flask import flash, redirect, render_template, request, url_for, session
from flask_login import (current_user, login_required, login_user, logout_user)
from flask_rq import get_queue

from . import account
# from .. import db
from ..email import send_email

from .models import User
from .forms import (ChangeEmailForm, ChangePasswordForm, CreatePasswordForm,
                    LoginForm, RegistrationForm, RequestResetPasswordForm,
                    ResetPasswordForm)

# add youngtip
import requests
from app import logger, backend_url, backend_headers, redis_ttl
import pickle
import time
# from app import redis_store
# from flask import make_response # using cookie
import httplib2
import urllib
from json import loads, dumps

@account.route('/login', methods=['GET', 'POST'])
def login():
    """Log in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        # TODO: requests error handling
        url = backend_url+'auth'
        data = {
            'email': form.email.data,
            'password': form.password.data
        }

        try:
            #processing start
            start_time = time.time()
            # r = requests.post(url, headers=backend_headers, data=data)

            h = httplib2.Http(".cache")
            #(resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=backend_headers)
            (resp, content) = h.request(url, "POST", body=dumps(data), headers=backend_headers)
            r = loads(content)
            logger.info(r)

            end_time = time.time()
            logger.info('login time >> '+str(end_time - start_time))
            #logger.info(r.json())
            
            if resp.status == 404:
                # r.raise_for_status()
                raise httplib2.ServerNotFoundError('restful api uri not found')
            else:
                if r['status'] == 'fail':
                    flash(r['message'], 'form-error')
                else:
                    # logger.info(r.json())
                    # make user email info
                    maked_email = ''
                    index_email = str(r['data']['email']).index('@')
                    for i in range(0,index_email):
                        if i ==0:
                            maked_email = maked_email+str(r['data']['email'])[0:1]
                        else:
                            maked_email = maked_email+'*'
                    maked_email = maked_email+str(r['data']['email'])[index_email:]

                    user = User(
                        id = r['data']['user_id'], 
                        username = r['data']['username'],
                        email = maked_email,
                        token = r['data']['token'],
                        is_active = r['data']['is_active'],
                        is_authenticated = True,
                        confirmed = r['data']['confirmed']
                    )
                    # using redis
                    """
                    redis_store.set(r.json()['data']['user_id'], pickle.dumps(user))
                    redis_store.expire(r.json()['data']['user_id'], redis_ttl) # set expire key, 6hr
                    """

                    # using cookie
                    """
                    resp = make_response(redirect(request.args.get('next') or url_for('main.index')))
                    resp.set_cookie('username', 'the username')
                    return resp
                    """

                    login_user(user, form.remember_me.data)
                    flash('You are now logged in. Welcome back!', 'success')

                    return redirect(request.args.get('next') or url_for('main.index'))
                    

        # except requests.exceptions.RequestException as e:
        except Exception as e:
            logger.error(e)
            flash('oops...'+'{'+str(e)+'}', 'form-error')

    return render_template('account/login.html', form=form)


@account.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user, and send them a confirmation email."""
    form = RegistrationForm()
    if form.validate_on_submit():
        # add youngtip using Frest backend
        url = backend_url+'users'
        data = {
                'email': form.email.data,
                'username': form.first_name.data+','+form.last_name.data,
                'password': form.password.data
                }
        try:

            r = requests.post(url, headers=backend_headers, data=data)
            logger.info(r.json())

            if r.status_code == 404:
                r.raise_for_status()
            else:
                if r.json()['status'] == 'fail':
                    flash(r.json()['message'], 'form-error')
                else:
                    user = User(
                        id = r.json()['id'],
                        username=form.first_name.data+','+form.last_name.data
                    )
                
                    confirm_token = user.generate_confirmation_token()
                    confirm_link = url_for('account.confirm', token=confirm_token, _external=True)
                    # TODO: RQ
                    get_queue().enqueue(
                        send_email,
                        recipient=form.email.data,
                        subject='Confirm Your Account',
                        template='account/email/confirm',
                        user=user,
                        confirm_link=confirm_link)
                    
                    # test mail
                    # send_email('youngtip@gmail.com','Confirm Your Account','account/email/confirm',user=user, confirm_link=confirm_link)
                    flash('A confirmation link has been sent to {}.'.format(form.email.data), 'warning')
                    return redirect(url_for('main.index'))
                    
        except requests.exceptions.RequestException as e:
            logger.error(e)
            flash('oops...'+'{'+str(e)+'}', 'form-error')

    return render_template('account/register.html', form=form)


@account.route('/logout')
@login_required
def logout():
    # POST /api/v@/logout Sign out
    # TODO: how do exception with async
    url = backend_url+'logout'
    backend_authed_headers = {
        'Accept': 'application/json',
        'Authorization': 'bearer ' + current_user.token
    }
    r = requests.post(url, headers=backend_authed_headers)

    # using remove redis with async
    # redis_store.delete(current_user.id)

    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


@account.route('/manage', methods=['GET', 'POST'])
@account.route('/manage/info', methods=['GET', 'POST'])
@login_required
def manage():
    """Display a user's account information."""
    return render_template('account/manage.html', user=current_user, form=None)


@account.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Respond to existing user's request to reset their password."""
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = RequestResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        logger.info(user)

        pass
        """
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_password_reset_token()
            reset_link = url_for(
                'account.reset_password', token=token, _external=True)
            get_queue().enqueue(
                send_email,
                recipient=user.email,
                subject='Reset Your Password',
                template='account/email/reset_password',
                user=user,
                reset_link=reset_link,
                next=request.args.get('next'))
        flash('A password reset link has been sent to {}.'
              .format(form.email.data), 'warning')
        return redirect(url_for('account.login'))
        """
    return render_template('account/reset_password.html', form=form)


@account.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset an existing user's password."""
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        pass
        """
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('Invalid email address.', 'form-error')
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.new_password.data):
            flash('Your password has been updated.', 'form-success')
            return redirect(url_for('account.login'))
        else:
            flash('The password reset link is invalid or has expired.',
                  'form-error')
            return redirect(url_for('main.index'))
        """
    return render_template('account/reset_password.html', form=form)


@account.route('/manage/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change an existing user's password."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        pass
        """
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been updated.', 'form-success')
            return redirect(url_for('main.index'))
        else:
            flash('Original password is invalid.', 'form-error')
        """
    return render_template('account/manage.html', form=form)


@account.route('/manage/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    """Respond to existing user's request to change their email."""
    form = ChangeEmailForm()
    if form.validate_on_submit():
        # TODO : call rest
        url = backend_url+'users/me'
        backend_authed_headers = {
            'Accept': 'application/json',
            'Authorization': 'bearer ' + current_user.token
        }
        data = {
            'change_email': form.email.data,
            'password': form.changeEmailPassword.data
        }

        start_time4 = time.time()
        logger.info('change email start time4 >> '+str(start_time4))

        try:
            h = httplib2.Http(".cache")
            #(resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=backend_headers)
            (resp, content) = h.request(url, "PUT", body=dumps(data), headers=backend_authed_headers)
            r = loads(content)

            start_time5 = time.time()
            logger.info('change email start time5 >> '+str(start_time5))
            logger.info('change email start time5 >> '+str(start_time5-start_time4))

            if resp.status == 404:
                # r.raise_for_status()
                raise httplib2.ServerNotFoundError('restful api uri not found')
            else:
                if r['status'] == 'fail':
                    flash(r['message'], 'form-error')
                else:
                    new_email = form.email.data
                    token = current_user.generate_email_change_token(new_email)
                    change_email_link = url_for('account.change_email', token=token, _external=True)
                    get_queue().enqueue(
                        send_email,
                        recipient=new_email,
                        subject='Confirm Your New Email',
                        template='account/email/change_email',
                        # current_user is a LocalProxy, we want the underlying user
                        # object
                        user=current_user._get_current_object(),
                        change_email_link=change_email_link)
                    
                    logout_user()
                    flash('A confirmation link has been sent to {}.'.format(new_email), 'warning')
                    flash('You have been logged out. relogin again with new email', 'info')

                    return redirect(url_for('main.index'))

        # except requests.exceptions.RequestException as e:
        except Exception as e:
            logger.error(e)
            flash('oops...'+'{'+str(e)+'}', 'form-error')

    return render_template('account/manage.html', form=form)


@account.route('/manage/change-email/<token>', methods=['GET', 'POST'])
@login_required
def change_email(token):
    """Change existing user's email with provided token."""
    if current_user.change_email(token):
        flash('Your email address has been updated.', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'error')
    return redirect(url_for('main.index'))


@account.route('/confirm-account')
@login_required
def confirm_request():
    """Respond to new user's request to confirm their account."""
    token = current_user.generate_confirmation_token()
    confirm_link = url_for('account.confirm', token=token, _external=True)
    """
    get_queue().enqueue(
        send_email,
        recipient=current_user.email,
        subject='Confirm Your Account',
        template='account/email/confirm',
        # current_user is a LocalProxy, we want the underlying user object
        user=current_user._get_current_object(),
        confirm_link=confirm_link)
    flash('A new confirmation link has been sent to {}.'.format(current_user.email), 'warning')
    """
    return redirect(url_for('main.index'))


@account.route('/confirm-account/<token>')
@login_required
def confirm(token):
    """Confirm new user's account with provided token."""
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm_account(token):
        flash('Your account has been confirmed.', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'error')
    return redirect(url_for('main.index'))


@account.route('/join-from-invite/<int:user_id>/<token>', methods=['GET', 'POST'])
def join_from_invite(user_id, token):
    """
    Confirm new user's account with provided token and prompt them to set
    a password.
    """
    if current_user is not None and current_user.is_authenticated:
        flash('You are already logged in.', 'error')
        return redirect(url_for('main.index'))
    """
    new_user = User.query.get(user_id)
    if new_user is None:
        return redirect(404)

    if new_user.password_hash is not None:
        flash('You have already joined.', 'error')
        return redirect(url_for('main.index'))

    if new_user.confirm_account(token):
        form = CreatePasswordForm()
        if form.validate_on_submit():
            new_user.password = form.password.data
            db.session.add(new_user)
            db.session.commit()
            flash('Your password has been set. After you log in, you can '
                  'go to the "Your Account" page to review your account '
                  'information and settings.', 'success')
            return redirect(url_for('account.login'))
        return render_template('account/join_invite.html', form=form)
    else:
        flash('The confirmation link is invalid or has expired. Another '
              'invite email with a new link has been sent to you.', 'error')
        token = new_user.generate_confirmation_token()
        invite_link = url_for(
            'account.join_from_invite',
            user_id=user_id,
            token=token,
            _external=True)
        get_queue().enqueue(
            send_email,
            recipient=new_user.email,
            subject='You Are Invited To Join',
            template='account/email/invite',
            user=new_user,
            invite_link=invite_link)
    """
    return redirect(url_for('main.index'))


@account.before_app_request
def before_request():
    """Force user to confirm email before accessing login-required routes."""
    # logger.info('youngtip >> '+str(request.endpoint))   
    # check_endpoint = ''
    if request.endpoint is not None:
        check_endpoint = request.endpoint[0:8]
    else:
        check_endpoint = None
    
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and check_endpoint != 'account.' \
            and request.endpoint != 'static':
        return redirect(url_for('account.unconfirmed'))


@account.route('/unconfirmed')
def unconfirmed():
    """Catch users with unconfirmed emails."""
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('account/unconfirmed.html')
