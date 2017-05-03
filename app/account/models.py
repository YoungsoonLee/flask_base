from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

class User():
	def __init__(self, id=None, username=None, email=None, password=None, permission=None, updated_at=None):
		self.id = id
		self.username = username
		self.email = email

	def generate_confirmation_token(self, expiration=604800):
		"""Generate a confirmation token to email a new user."""
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})