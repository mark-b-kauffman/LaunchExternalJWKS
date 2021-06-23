import datetime
import os
import pprint
import uuid
import urllib
import webbrowser
import json
import base64

from distutils import util

import string
import secrets

from urllib.parse import urlparse
from urllib.parse import unquote

from tempfile import mkdtemp

from flask import Flask, jsonify, request, render_template, url_for, redirect, Response
from flask_caching import Cache
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from flask_debugtoolbar import DebugToolbarExtension
from flask.helpers import make_response

from werkzeug.exceptions import Forbidden

from pylti1p3.contrib.flask import FlaskOIDCLogin, FlaskMessageLaunch, FlaskRequest, FlaskCacheDataStorage
from pylti1p3.deep_link_resource import DeepLinkResource
from pylti1p3.grade import Grade
from pylti1p3.lineitem import LineItem
from pylti1p3.tool_config import ToolConfJsonFile
from pylti1p3.registration import Registration

import Config

import RestAuthController



class ReverseProxied(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)


app = Flask('ultra-extension-framework-sample', template_folder='templates', static_folder='static')

app.wsgi_app = ReverseProxied(app.wsgi_app)

config = {
    "DEBUG": False,
    "ENV": "production",
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 600,
    "SECRET_KEY": "EF186261-4F2E-4CCC-9C5C-6935CF0262F4",
    "SESSION_TYPE": "filesystem",
    "SESSION_FILE_DIR": mkdtemp(),
    "SESSION_COOKIE_NAME": "flask-session-id",
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SECURE": True,  # should be True in case of HTTPS usage (production)
    "SESSION_COOKIE_SAMESITE": "None",  # should be 'None' in case of HTTPS usage (production)
    "DEBUG_TB_INTERCEPT_REDIRECTS": False
}
app.config.from_mapping(config)

cache = Cache(app)

toolbar = DebugToolbarExtension(app)

login_manager = LoginManager()
login_manager.init_app(app)


PAGE_TITLE = 'Ultra Extension Framework Sample'

class User(UserMixin):

    def __init__(self, user_id):
        self.id = user_id

class ExtendedFlaskMessageLaunch(FlaskMessageLaunch):

    def validate_nonce(self):
        """
        Probably it is bug on "https://lti-ri.imsglobal.org":
        site passes invalid "nonce" value during deep links launch.
        Because of this in case of iss == http://imsglobal.org just skip nonce validation.
        """
        iss = self.get_iss()
        deep_link_launch = self.is_deep_link_launch()
        if iss == "http://imsglobal.org" and deep_link_launch:
            return self
        return super(ExtendedFlaskMessageLaunch, self).validate_nonce()


def get_lti_config_path():
    return os.path.join(app.root_path, 'lti.json')


def get_launch_data_storage():
    return FlaskCacheDataStorage(cache)


def get_jwk_from_public_key(key_name):
    key_path = os.path.join(app.root_path, '..', 'configs', key_name)
    f = open(key_path, 'r')
    key_content = f.read()
    jwk = Registration.get_jwk(key_content)
    f.close()
    return jwk

def parseUserId():

    user_id = current_user.id.split()

    return user_id[0], user_id[1]


@login_manager.unauthorized_handler
def unauthorized():
    return(Response('Must be a valid LTI connection.', status=403))

@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        return User(user_id)
    return None

@app.route('/', methods=['GET'])
def test():
    return('<h1>Your docker container is sucessfully being served by ngrok from your desktop!</h1>')

@app.route('/jwks/', methods=['GET'])
def get_jwks():
    print('Enter get_jwks()')
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    return jsonify({'keys': tool_conf.get_jwks()})

@app.route('/login/', methods=['GET', 'POST'])
def login():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    launch_data_storage = get_launch_data_storage()

    flask_request = FlaskRequest()
    target_link_uri = flask_request.get_param('target_link_uri')
    
    if not target_link_uri:
        raise Exception('Missing "target_link_uri" param')

    oidc_login = FlaskOIDCLogin(flask_request, tool_conf, launch_data_storage=launch_data_storage)
    return oidc_login\
        .enable_check_cookies()\
        .redirect(target_link_uri)


@app.route('/launch/', methods=['HEAD','GET','POST'])
def launch():
    tool_conf = ToolConfJsonFile(get_lti_config_path())
    flask_request = FlaskRequest()
    launch_data_storage = get_launch_data_storage()
    message_launch = ExtendedFlaskMessageLaunch(flask_request, tool_conf, launch_data_storage=launch_data_storage)
    message_launch_data = message_launch.get_launch_data()
    pprint.pprint(message_launch_data)

    tpl_kwargs = {
        'page_title': PAGE_TITLE,
        'is_deep_link_launch': message_launch.is_deep_link_launch(),
        'launch_data': message_launch.get_launch_data(),
        'launch_id': message_launch.get_launch_id(),
        'curr_user_name': message_launch_data.get('name', '')
    }
    
    """ 
    We could do the launch to the external page here. The following which does the 3LO with REST APIs
    back to the Learn system is not necessary. It's an artifact of project this one was leveraged from.
    We left it here for the most part to demonstrate how one can pass data through the 3LO process
    using the state parameter. The state is an opaque value that doesn't get modified by the 
    developer portal or by Learn. We take the external URL that will be launched to and include it as
    a portion of the state to be pulled out on the other side of 3LO. It's the only way across. 
    Attempts to pass the data by adding an additional parameter to the request for a authroization code
    will fail because those will be dropped. I.E setting your redirect_uri to .../authcode/?launch_url=URL
    does not work.
    https://stackabuse.com/encoding-and-decoding-base64-strings-in-python/
    """

    learn_url = message_launch_data['https://purl.imsglobal.org/spec/lti/claim/tool_platform']['url'].rstrip('/')
    # MUST include a custom parameter like 'external_url=https://www.foodies.com' in the custom params
    external_url = message_launch_data['https://purl.imsglobal.org/spec/lti/claim/custom']['external_url'].rstrip('/')
    state = str(uuid.uuid4()) + f'&launch_url={external_url}'
    message_bytes = state.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    params = {
        'redirect_uri' : Config.config['app_url'] + '/authcode/',
        'response_type' : 'code',
        'client_id' : Config.config['learn_rest_key'],
        'scope' : '*',
        'state' : base64_message
    }

    encodedParams = urllib.parse.urlencode(params)

    get_authcode_url = learn_url + '/learn/api/public/v1/oauth2/authorizationcode?' + encodedParams

    print("authcode_URL: " + get_authcode_url, flush=True)

    return(redirect(get_authcode_url))

@app.route('/authcode/', methods=['GET', 'POST'])
def authcode():
    
    authcode = request.args.get('code', '')
    base64_message = request.args.get('state', '')
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    state = message_bytes.decode('ascii')
    launch_url = state.split("&launch_url=",1)[1]

    print ("authcode: " + authcode, flush=True)
    print ("base64_message: " + base64_message, flush=True)
    print ("state: " + state, flush=True)
    print ("launch_url: " + launch_url, flush=True)
    
    
    restAuthController = RestAuthController.RestAuthController(authcode)
    restAuthController.setToken()
    token = restAuthController.getToken()
    uuid = restAuthController.getUuid()

    login_user(User(uuid))

    return render_template('external.html', launch_url=launch_url)

if __name__ == '__main__':
    restAuthController = None
    app.run(host='0.0.0.0', port=5000)