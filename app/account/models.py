from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

# add youngtip
from app import login_manager
import requests
from app import logger, backend_url, backend_headers
from flask import Flask, session

class User():
	def __init__(self, id=None, username=None, email=None, token=None, is_active=None, is_authenticated=None, is_anonymous=None, confirmed=None):
		self.id = id
		self.username = username
		self.email = email
		self.token = token # hashed token
		self.is_active = is_active # active or close
		self.is_authenticated = is_authenticated # logged in or not
		self.is_anonymous = is_anonymous # dummy data for flask-login (using guest or not)
		self.confirmed = confirmed

	def generate_confirmation_token(self, expiration=604800):
		"""Generate a confirmation token to email a new user."""
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})

	def get_id(self):
		# changed id to token for user_loader
		_data = {	
			'token' : self.token,
			'id': self.id
		}
		return _data

	def confirm_account(self, token):
		"""Verify that the provided token is for this user's id."""
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except (BadSignature, SignatureExpired):
			return False

		# change compare with str
		if str(data.get('confirm')) != str(self.id):
			return False

		# TODO: send to backend for updating confirm field
		# TODO: check requests exception
		url = backend_url+'confirm'
		data = {
			'token': token,
			'id': data.get('confirm')
		}
		r = requests.post(url, headers=backend_headers, data=data)
		try:
			if r.status_code == 404:
				r.raise_for_status()
			else:
				if r.json()['status'] == 'fail':
					return False
		except requests.exceptions.RequestException as e:
			logger.error(e)
			return False

		"""
		self.confirmed = True
		db.session.add(self)
		db.session.commit()
		"""

		return True

@login_manager.user_loader
def _user_loader(user):
	# return User.query.get(int(user_id))
	
	# TODO: check exceptopn of requests
	backend_headers['Authorization'] = 'bearer ' + user['token']
	#url = backend_url+'users/'+str(user['id'])
	url = backend_url+'users/me'
	r = requests.get(url, headers=backend_headers).json()
	logger.info(r)
	
	if r['status'] == 'fail':
		return User(
				id=None, 
				username=None,
				email=None,
				token=None,					# hashed token...
				is_active=None, 
				is_authenticated=None,
				is_anonymous=None,
				confirmed=None)
	else:
		return User(
				id=str(r['id']), 
				username=r['username'],
				email=r['email'], 
				token=user['token'],		# hashed token...
				is_active=r['is_active'], 
				is_authenticated=True,
				is_anonymous=False,
				confirmed=r['confirmed'])


