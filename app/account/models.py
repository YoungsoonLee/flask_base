from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

# add youngtip
from app import login_manager
import requests
from app import logger, backend_url, backend_headers
from flask import Flask, session

class User():
	def __init__(self, id=None, username=None, token=None, is_active=None, is_authenticated=None, confirmed=None):
		self.id = id
		self.username = username
		self.token = token
		self.is_active = is_active
		self.is_authenticated = is_authenticated
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

@login_manager.user_loader
def _user_loader(user):
	# return User.query.get(int(user_id))
	# GET /api/v@/users/<prefix(me or user_id)> Return user information
	backend_headers['Authorization'] = 'bearer ' + user['token']
	url = backend_url+'users/'+str(user['id'])
	r = requests.get(url, headers=backend_headers).json()
	#logger.info(r)
	# clear email for security
	return User(
			id=str(r['id']), 
			username=r['username'], 
			is_active=True, 
			is_authenticated=True,
			confirmed=True)


