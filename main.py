#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#



import hashlib
import webapp2
import os
from google.appengine.api import urlfetch
import urllib
import json
from webapp2_extras import sessions
from webapp2_extras import jinja2

# Course: cs496
# Assignment: OAuth 2.0 Implementation
# Date: 02/12/16
# Username: kirchnch
# Name: Chris Kirchner
# Email: kirchnch@oregonstat.edu
# Description: a basic oauth2.0 handler to gain access to user's google+ profile with 'email' scope

client_id='114434251902-ri6e683fh0ikdftdbb68dba2t3a34sd1.apps.googleusercontent.com'
client_secret='LKG4HApwdO-ZU1FO3fNR6ldW'

# https://cloud.google.com/appengine/docs/python/getting-started/generating-dynamic-content-templates
# JINJA_ENVIRONMENT = jinja2.Environment(
#     loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
#     extensions=['jinja2.ext.autoescape'],
#     autoescape=True)

# http://webapp2.readthedocs.io/en/latest/guide/extras.html
# customized handler to use sessions for state variable and jinja2 html templating
class BaseHandler(webapp2.RequestHandler):

    def dispatch(self):
        self.session_store = sessions.get_store(request=self.request)
        try:
            # dispatch request
            webapp2.RequestHandler.dispatch(self)
        finally:
            # save sessions
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # return session with default cookie
        return self.session_store.get_session()

    # http://webapp2.readthedocs.io/en/latest/api/webapp2_extras/jinja2.html
    @webapp2.cached_property
    def jinja2(self):
        # returns jinja2 renderer cached in app registry
        return jinja2.get_jinja2(app=self.app)

    #wrapper for rendering template
    def render_response(self, _template, **context):
        # renders a template and writes the result to the response
        rv = self.jinja2.render_template(_template, **context)
        self.response.write(rv)

class MainHandler(BaseHandler):

    def get(self):
        """
        gets the redirect request to Google's oauth handler
        """
        # capture the state as a hash per https://developers.google.com/identity/protocols/OpenIDConnect
        self.session['state'] = hashlib.sha256(os.urandom(1024)).hexdigest()
        # setup oauth redirect request
        oauth_request = dict(
            response_type='code',
            client_id=client_id,
            redirect_uri='https://oauth2-wk5-cs496.appspot.com/oauth',
            scope='email',
            state=self.session['state'],
            access_type='online',
            prompt='select_account'
        )
        param_query = urllib.urlencode(oauth_request)
        return self.redirect('https://accounts.google.com/o/oauth2/v2/auth?'+param_query)


class OAuthHandler(BaseHandler):

    # need to handle state
    def get(self):
        """
        gets the access code after the user grants permissions to this client
        """
        # respond with error code on error
        if self.request.get('error'):
            self.response.status = 400
            self.response.write('error')
        # error handling taken from https://developers.google.com/identity/protocols/OpenIDConnect
        elif self.request.get('state') != self.session['state']:
            self.response.status = 401
            self.response.headers['Content-Type'] = 'application/json'
            self.response.write(json.dumps('Invalid state parameter.'))
        # process the code if there is one
        elif self.request.get('code'):
            # setup code->token exchange request with server
            token_request = dict(
                code=self.request.get('code'),
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri='https://oauth2-wk5-cs496.appspot.com/oauth',
                grant_type='authorization_code'
            )
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            # request token with authorization code
            token = urlfetch.fetch(
                'https://www.googleapis.com/oauth2/v4/token',
                payload=urllib.urlencode(token_request),
                method=urlfetch.POST,
                headers=headers
            )

            # process token
            token_json = json.loads(token.content)
            access_token = token_json.get('access_token', None)
            expires = token_json.get('expires_in', None)

            # error handling inspired by code in oauth docs
            # https://developers.google.com/identity/protocols/OAuth2WebServer
            if access_token is None or expires <= 0:
                return self.redirect('/')
            # request access to user permissions
            else:
                # add token to header as logs usually capture url queries
                headers = {
                    'Authorization': 'Bearer {}'.format(access_token)
                }
                # fetch user profile
                userinfo_request = urlfetch.fetch('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
                # process user info with needed variables
                userinfo = json.loads(userinfo_request.content)
                context = dict(
                    first_names=userinfo['given_name'],
                    last_names=userinfo['family_name'],
                    plus_page=userinfo['link'],
                    state=self.session['state']
                )
                # render html with user info
                self.render_response('index.html', **context)

# testing handler for jinja2
class Jinja(BaseHandler):

    def get(self):
        context = dict(
            first_names='Chris',
            last_names='Kirchner',
            plus_page='https://plus.google.com/100825539377022763720',
            state=hashlib.sha256(os.urandom(1024)).hexdigest()
        )
        self.render_response('index.html', **context)

# setup secretes with super secret password
config = dict()
config['webapp2_extras.sessions'] = dict(secret_key='secret_key')

# setup routes
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/oauth', OAuthHandler),
    ('/test', Jinja)
], debug=True, config=config)
