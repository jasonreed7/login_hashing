# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
	return USER_RE.match(username)

def valid_password(password):
	return PASSWORD_RE.match(password)

def valid_email(email):
	return EMAIL_RE.match(email)

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(h):
	return "%s|%s" % (h, hash_str(h))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

class User(db.Model):
	username = db.StringProperty(required=True)
	password_hash = db.StringProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainPage(Handler):
	def get(self):
		self.render("form.html")

	def post(self):
		username = {'value': self.request.get("username"),
		'error': False,
		'taken': False}
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = {'value': self.request.get("email"),
		'error': False}
		password_error = False
		verify_error = False

		if not(username['value'] and valid_username(username['value'])):
			username['error'] = True
		else:
			q = User.all()
			username_match = q.filter('username=', username)
			if(username.match.count() > 0):
				username['taken'] = True

		if not(password and valid_password(password)):
			password_error = True

		if not(password == verify):
			verify_error = True
		
		if email['value'] and not(valid_email(email['value'])):
			email['error'] = True 

		if username['error'] or username['taken'] or password_error or verify_error or email['error']:
			self.render("form.html", username = username, password_error = password_error, verify_error = verify_error, email = email)
		else:


			# Hash password and store user info
			password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
			user = User(username=username['value'], password_hash=password)
			user.put()

			id = user.key().id()
			id_cookie = 'id=' + make_secure_val(id)

			id_cookie += '; Path=/'

			self.response.headers.add_header('Set-Cookie', id_cookie)

			self.redirect('/welcome')

class WelcomeHandler(Handler):
	def get(self):
		id_cookie = self.request.cookies.get('id')
		id = check_secure_val(id_cookie)
		if id:
			user = User.get_by_id(id)
			if user:
				self.write('<div>Welcome ' + user.username + '</div>')
		else:
			self.write('Invalid authorization')

app = webapp2.WSGIApplication([
	('/signup', MainPage),
	('/welcome', WelcomeHandler)
], debug=True)
