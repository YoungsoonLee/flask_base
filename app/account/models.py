from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

# add youngtip
from app import login_manager
import requests
from app import logger, backend_url, backend_headers, redis_ttl
# from flask import Flask, session

# add youngtip
# from app import redis_store
import pickle
from json import loads, dumps
import ast

import httplib2
import urllib

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

	def get_id(self):
		# changed id to token for user_loader
		_data = {	
			'token' : self.token, # hashed token
			'id': self.id,
			'username': self.username,
			'email': self.email,
			'is_active': self.is_active,
			'is_authenticated': True,
			'is_anonymous': False,
			'confirmed': self.confirmed
		}
		return _data


	def confirm_account(self, token):
		"""Verify that the provided token is for this user's id."""
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except (BadSignature, SignatureExpired):
			return None

		# change compare with str
		if str(data.get('confirm')) != str(self.id):
			return None

		# TODO: send to backend for updating confirm field
		url = backend_url+'confirm'
		data = {
			'token': token,
			'id': data.get('confirm')
		}

		try:
			h = httplib2.Http(".cache")
			(resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=backend_headers)
			r = loads(content)
			logger.info(r)

			if resp.status in (404,405) or resp.status < 200:
				raise httplib2.ServerNotFoundError('restful api uri not found. {}'.format(r['message']))
			else:
				if r['status'] == 'fail':
					return None
				else:
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

					return user

		except Exception as e:
			logger.error(e)
			# flash('oops...'+'{'+str(e)+'}', 'form-error')
			return None


		"""
		self.confirmed = True
		db.session.add(self)
		db.session.commit()
		"""
		
	def generate_confirmation_token(self, expiration=604800): # expire 7 days
		"""Generate a confirmation token to email a new user."""
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})

	def generate_email_change_token(self, new_email, expiration=3600): # 1 hour
		"""Generate an email change token to email an existing user."""
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'change_email': self.id, 'new_email': new_email})

	def generate_password_reset_token(self, expiration=3600): # 1 hour
		"""
		Generate a password reset change token to email to an existing user.
		"""
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'reset': self.id})

	"""
	def reset_password(self, token, new_password):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except (BadSignature, SignatureExpired):
			return False
		if data.get('reset') != self.id:
			return False
		return True
	"""


def check_reset_password_token(token):
	s = Serializer(current_app.config['SECRET_KEY'])
	try:
		data = s.loads(token)
	except (BadSignature, SignatureExpired) as e:
		logger.info(e)
		return None

	return str(data.get('reset'))


@login_manager.user_loader
def _user_loader(user):
	# return User.query.get(int(user_id))
	
	if type(user) != dict:
		user = ast.literal_eval(user)

	user = User(
				id=str(user['id']), 
				username=user['username'],
				email=user['email'], 
				token=user['token'],		# hashed token...
				is_active=user['is_active'], 
				is_authenticated=user['is_authenticated'],
				is_anonymous=user['is_anonymous'],
				confirmed=user['confirmed'])

	return user

	# using redis
	"""
	empty_user = User(
				id=None, 
				username=None,
				email=None,
				token=None,					# hashed token...
				is_active=None, 
				is_authenticated=None,
				is_anonymous=None,
				confirmed=None)

	if type(user) != dict:
		user = ast.literal_eval(user)
	unpacked_user = redis_store.get(user['id'])

	if unpacked_user is None and user['id'] is None:
		return empty_user
	elif unpacked_user is None and user['id'] is not None:
		#  call rest and reset redis
		logger.info('call REST and reset redis')
		backend_headers['Authorization'] = 'bearer ' + user['token']
		url = backend_url+'users/me'
		r = requests.get(url, headers=backend_headers).json()
		# logger.info(r)

		if r['status'] == 'fail':
			return empty_user
		else:
			user = User(
				id=str(r['id']), 
				username=r['username'],
				email=r['email'], 
				token=user['token'],		# hashed token...
				is_active=r['is_active'], 
				is_authenticated=True,
				is_anonymous=False,
				confirmed=r['confirmed'])

			redis_store.set(r['id'], pickle.dumps(user))
			redis_store.expire(r['id'], redis_ttl) # set expire key, second

			return user
	else:
		# check ttl and re-fresh redis
		logger.info('ttl >> '+str(redis_store.ttl(user['id'])))
		# check ttl and reflash
		if redis_store.ttl(user['id']) <= 30:
			logger.info('under ttl 30 call REST and reset redis')
			backend_headers['Authorization'] = 'bearer ' + user['token']
			url = backend_url+'users/me'
			r = requests.get(url, headers=backend_headers).json()
			# logger.info(r)

			if r['status'] == 'fail':
				return empty_user
			else:
				user = User(
					id=str(r['id']), 
					username=r['username'],
					email=r['email'], 
					token=user['token'],		# hashed token...
					is_active=r['is_active'], 
					is_authenticated=True,
					is_anonymous=False,
					confirmed=r['confirmed'])

				redis_store.set(r['id'], pickle.dumps(user))
				redis_store.expire(r['id'], redis_ttl) # set expire key, second

				return user
		else:
			unpacked_user = pickle.loads(redis_store.get(user['id']))
			return User(
					id=str(unpacked_user.id), 
					username=unpacked_user.username,
					email=unpacked_user.email, 
					token=unpacked_user.token,		# hashed token...
					is_active=unpacked_user.is_active, 
					is_authenticated=True,
					is_anonymous=False,
					confirmed=unpacked_user.confirmed)
	"""

"""
def make_user(r_user):
	# more consider
	'''
	maked_email = ''
	index_email = str(r_user['email']).index('@')
	for i in range(0,index_email):
		if i ==0:
			maked_email = str(r_user['email'])[0:1]
		else:
			maked_email = maked_email+'*'
	maked_email = maked_email+str(r_user['email'])[index_email:]
	'''

	user = User(
		id = r_user['id'], 
		username = r_user['username'],
		# email = maked_email,
		email = r_user['email'],
		token = r_user['token'],
		is_active = r_user['is_active'],
		is_authenticated = True,
		confirmed = r_user['confirmed']
		)

	return user
"""

