import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from dotenv import load_dotenv

load_dotenv()

# SQLITE CONFIG
import sqlite3
conn  =  sqlite3.connect('users.sqlite3', check_same_thread=False)
cursor = conn.cursor()


app = Flask("flask-login-app")
app.secret_key = os.getenv("APP_SECRET_KEY")

# https 만을 지원하는 기능을 http에서 테스트할 때 필요한 설정
# to allow Http traffic for local dev
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_uri="http://localhost:3000/callback"
)

flow2 = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_uri="http://localhost:3000/login/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/")
def index():
    if "google_id" in session:
        return render_template('index.html', logged_in=True, username=session['name'])   
        # return "Hello World <a href='/login'><button>Login</button></a>"
    else: 
        return render_template('index.html', logged_in=False)   
    
@app.route('/googlelogin')
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    print(session["state"])
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    # 세션에 'state' 값이 있는지 확인
    # if 'state' not in session:
    #     abort(400, "Session state missing")

    # 'google_id'가 세션에 없는 경우에만 토큰을 가져옴
    if "google_id" not in session:
        flow.fetch_token(authorization_response=request.url)

        print('=======' * 10);
        print(request)
        print('=======' * 10);
        print(request.args.get("state"))
        
#        if session['state'] != request.args.get('state'):
#            abort(500)  # State does not match!
            
        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        # 사용자 정보 가져오기
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        # Store user ID and name in session
        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email")
        session["picture"] = id_info.get("picture")
        
        conn  =  sqlite3.connect('users.sqlite3')
        cursor = conn.cursor()
        
        sql = "INSERT INTO users(username, user_email, user_oauth_id, user_oauth_platform) VALUES(?,?,?,?)"
        cursor.execute(sql,(id_info.get("name"),id_info.get("email"),id_info.get("sub"),"google"))
        conn.commit()    

        return redirect("/dashboard")
    else:
        return redirect("/")


@app.route("/dashboard")
@login_is_required
def protected_area():
    try:
        # Construct a greeting message with more user information
        greeting_message = f""
        greeting_message += f"<h1>Hello</h1>"
        greeting_message += f"Your GoogleID  : {session['google_id']}!<br/>"
        greeting_message += f"Your name  : {session['name']}!<br/>"
        greeting_message += f"Your email : {session['email']}<br/>"
        greeting_message += f"<img src='{session['picture']}' alt='Profile Picture'><br/></br/>"
        greeting_message += "<a href='/logout'><button>Logout</button></a>"
        
        return greeting_message
    except Exception as e:
        # Handle exceptions gracefully
        return f"An error occurred: {e}", 500
    
@app.route("/logout")
def logout():
    if "google_id" in session:
        session.clear()
        return redirect("/")
    else :
        return redirect("/")


@app.route("/register")
def register_page():
    return redirect("/")


@app.route('/signin')
def sign_in():
    return render_template('signin.html')


@app.route('/googlelogin_callback')
def google_login_callback():
    authorization_url, state = flow2.authorization_url()
    session["state2"] = state
    return redirect(authorization_url)

@app.route("/login/callback")
def login_callback():
    if "google_id" in session: 
        return abort(404)
    
    flow2.fetch_token(authorization_response=request.url)

    # # Check if "state2" key exists in session
    # if "state2" not in session:
    #     abort(500)  # State does not exist in session!

    # if not session["state2"] == request.args["state"]:
    #     abort(500)  # State does not match!

    credentials = flow2.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    conn  =  sqlite3.connect('users.sqlite3')
    cursor = conn.cursor()

    sql = "SELECT * FROM users WHERE user_oauth_id == ?"
    cursor.execute(sql, (id_info.get("sub"),))
    row = cursor.fetchall()
    if row: 
        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email")
        # return render_template('index.html', logged_in=True, username=session['name'])
        return redirect('/')

    else:
        return redirect('/register')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
