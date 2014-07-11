from flask import Flask, url_for, session, request, jsonify
from flask.ext.login import LoginManager, login_required, current_user, login_user, logout_user
from flask_oauthlib.client import OAuth
from mwork.users.models import User
from flask import redirect

CLIENT_ID = "ZpJMQquTwXI3Xq86MUljFtEdOwTptIJOexVZuiJ5"
CLIENT_SECRET = 'rYK9SCO4rYPJJd3gThfSo7PtRj6lowIDAsuxqMD81PYmmeioSB'
app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
oauth = OAuth(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(userid):
    # Return an instance of the User model
    return User.objects(id=userid).first()

mwork = oauth.remote_app(
    'mwork',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': 'email refcode'},
    base_url='http://127.0.0.1:21000/api/',
    request_token_url=None,
    access_token_url='http://127.0.0.1:21000/oauth2/oauth/token',
    authorize_url='http://127.0.0.1:21000/oauth2/oauth/authorize')


@app.route('/')
@login_required
def index():
    if 'mwork_token' in session:
        data = mwork.get('me').data
    if data:
        try:
            print data
            return jsonify(data)
        except Exception, e:
            return redirect('/logout')
    return "Hello %s" % current_user.username


@app.route('/login')
def login():
    next_url = request.args.get('next', "/")
    return mwork.authorize(callback=url_for('authorized', _external=True))


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route('/authorized')
@mwork.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )

    session['mwork_token'] = (resp['access_token'], '')

    me = mwork.get("me")
    u = User.objects(username=me.data['username']).first()
    login_user(u)
    return redirect("/")


@mwork.tokengetter
def get_oauth_token():
    return session.get('mwork_token')

if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='localhost', port=8000)
