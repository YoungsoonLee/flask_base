from flask import flash, redirect, render_template, request, url_for, session
from flask_login import (current_user, login_required, login_user, logout_user)
from flask_rq import get_queue

from . import account
# from .. import db
from ..email import send_email

from .models import User, check_reset_password_token
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

            h = httplib2.Http(".cache")
            (resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=backend_headers)
            r = loads(content)
            logger.info(r)

            end_time = time.time()
            logger.info('login time >> '+str(end_time - start_time))
            
            if resp.status in (404,405) or resp.status < 200:
                raise httplib2.ServerNotFoundError('restful api uri not found. {}'.format(r['message']))
            else:
                if r['status'] == 'fail':
                    flash(r['message'], 'form-error')
                else:
                    # more consider
                    """
                    maked_email = ''
                    index_email = str(r_user['email']).index('@')
                    for i in range(0,index_email):
                        if i ==0:
                            maked_email = str(r_user['email'])[0:1]
                        else:
                            maked_email = maked_email+'*'
                    maked_email = maked_email+str(r_user['email'])[index_email:]
                    """
                    # for login info
                    user = User(
                        id = r['data']['user_id'], 
                        username = r['data']['username'],
                        # email = maked_email,
                        email = r['data']['email'],
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
                'username': form.nickname.data,
                'password': form.password.data
                }
        try:
            h = httplib2.Http(".cache")
            (resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=backend_headers)
            r = loads(content)
            logger.info(r)

            if resp.status in (404,405) or resp.status < 200:
                raise httplib2.ServerNotFoundError('restful api uri not found')
            else:
                if r['status'] == 'fail':
                    flash(r['field'] +' '+ r['message'], 'form-error')
                else:
                    # for send mail
                    user = User(
                        id = r['id'],
                        username=form.nickname.data
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
                    
                    flash('A confirmation link has been sent to {}.'.format(form.email.data), 'warning')
                    return redirect(url_for('main.index'))
                    
        # except requests.exceptions.RequestException as e:
        except Exception as e:
            logger.error(e)
            flash('oops...'+'{'+str(e)+'}', 'form-error')

    return render_template('account/register.html', form=form)


@account.route('/logout')
@login_required
def logout():
    # POST /api/v@/logout Sign out
    url = backend_url+'logout'
    backend_authed_headers = {
        'Content-Type':'application/x-www-form-urlencoded', 
        'Accept': 'application/json',
        'Authorization': 'bearer ' + current_user.token
    }

    h = httplib2.Http(".cache")
    (resp, content) = h.request(url, "POST", headers=backend_authed_headers)

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


# forgot-password
@account.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Respond to existing user's request to reset their password."""
    form = RequestResetPasswordForm()

    if form.validate_on_submit():
        # TODOO: call to restful
        url = backend_url+'auth'
        data = {
                'email': form.email.data
                }
        try:
            h = httplib2.Http(".cache")
            (resp, content) = h.request(url, "PUT", body=urllib.parse.urlencode(data), headers=backend_headers)
            r = loads(content)
            logger.info(r)

            if resp.status in (404,405) or resp.status < 200:
                raise httplib2.ServerNotFoundError('restful api uri not found')
            else:
                if r['status'] == 'fail':
                    flash(r['message'], 'form-error')
                else:
                    # for send mail
                    user = User(
                        id = r['data']['id'],
                        username=r['data']['username']
                    )

                    token = user.generate_password_reset_token() # reset token
                    reset_link = url_for('account.reset_password', token=token, _external=True)

                    get_queue().enqueue(
                        send_email,
                        recipient=form.email.data,
                        subject='Reset Your Password',
                        template='account/email/reset_password',
                        user=user,
                        reset_link=reset_link,
                        next=request.args.get('next'))

                    flash('A password reset link has been sent to {}.'
                        .format(form.email.data), 'warning')
                    return redirect(url_for('account.login'))

        except Exception as e:
            logger.error(e)
            flash('oops...'+'{'+str(e)+'}', 'form-error')
    return render_template('account/reset_password.html', form=form)


@account.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset an existing user's password."""
    form = ResetPasswordForm()

    if form.validate_on_submit():
        # TODOO: call to restful
        url = backend_url+'auth/reset_password'
        data = {
                'email': form.email.data,
                'new_password': form.new_password.data
                }

        if check_reset_password_token(token) is None:
            flash('The password reset link is invalid or has expired.', 'form-error')
            # return redirect(url_for('main.index')) # not working, why?
        else:
            try:
                h = httplib2.Http(".cache")
                (resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=backend_headers)
                r = loads(content)
                logger.info(r)

                if resp.status in (404,405) or resp.status < 200:
                    raise httplib2.ServerNotFoundError('restful api uri not found')
                else:
                    if r['status'] == 'fail':
                        flash(r['message'], 'form-error')
                    else:
                        flash('Your password has been updated.', 'form-success')
                        return redirect(url_for('account.login'))
            except Exception as e:
                logger.error(e)
                flash('oops...'+'{'+str(e)+'}', 'form-error')
    return render_template('account/reset_password.html', form=form)


@account.route('/manage/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change an existing user's password."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        url = backend_url+'auth/reset_password'
        backend_authed_headers = {
            'Content-Type':'application/x-www-form-urlencoded', 
            'Accept': 'application/json',
            'Authorization': 'bearer ' + current_user.token
        }
        data = {
            'email': current_user.email,
            'old_password': form.old_password.data,
            'new_password': form.new_password.data
        }

        try:
            h = httplib2.Http(".cache")
            (resp, content) = h.request(url, "PUT", body=urllib.parse.urlencode(data), headers=backend_authed_headers)
            r = loads(content)
            logger.info(r)

            if resp.status in (404,405) or resp.status < 200:
                raise httplib2.ServerNotFoundError('restful api uri not found')
            else:
                if r['status'] == 'fail':
                    flash(r['message'], 'form-error')
                else:
                    logout_user()
                    flash('Your password has been updated.', 'form-success')
                    flash('You have been logged out. relogin again with new email', 'info')
                    return redirect(url_for('account.login'))
        except Exception as e:
            logger.error(e)
            flash('oops...'+'{'+str(e)+'}', 'form-error')
            
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
            'Content-Type':'application/x-www-form-urlencoded', 
            'Accept': 'application/json',
            'Authorization': 'bearer ' + current_user.token
        }
        data = {
            'change_email': form.change_email.data,
            'changeEmailPassword': form.changeEmailPassword.data
        }

        try:
            start_time = time.time()

            h = httplib2.Http(".cache")
            (resp, content) = h.request(url, "PUT", body=urllib.parse.urlencode(data), headers=backend_authed_headers)
            r = loads(content)
            logger.info(r)

            end_time = time.time()
            logger.info('change email start time5 >> '+str(end_time-start_time))

            if resp.status in (404,405) or resp.status < 200:
                raise httplib2.ServerNotFoundError('restful api uri not found. {}'.format(r['message']))
            else:
                if r['status'] == 'fail':
                    if r['field'] == 'changeEmailPassword':
                        r['field'] = 'Password'
                    flash(r['field']+' '+r['message'], 'form-error')
                else:
                    new_email = form.change_email.data
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

        except Exception as e:
            flash('oops...'+'{'+str(e)+'}', 'form-error')

    return render_template('account/manage.html', form=form)


@account.route('/manage/change-email/<token>', methods=['GET', 'POST'])
@login_required
def change_email(token):
    """Change existing user's email with provided token."""
    # TODO: !!!!
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
    get_queue().enqueue(
        send_email,
        recipient=current_user.email,
        subject='Confirm Your Account',
        template='account/email/confirm',
        # current_user is a LocalProxy, we want the underlying user object
        user=current_user._get_current_object(),
        confirm_link=confirm_link)
    flash('A new confirmation link has been sent to {}.'.format(current_user.email), 'warning')
    return redirect(url_for('main.index'))


@account.route('/confirm-account/<token>')
@login_required
def confirm(token):
    """Confirm new user's account with provided token."""
    if current_user.confirmed:
        return redirect(url_for('main.index'))

    user = current_user.confirm_account(token) # call rest and reflash user info

    if user is not None:
        flash('Your account has been confirmed.', 'success')
        # reload user info 
        login_user(user)

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
