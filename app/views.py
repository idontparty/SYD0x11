from app import app
from flask import Flask, request, make_response, render_template
import base64

# views.py
# by SteffnJ
# For SecTalks SYD0x11 CTF
# Yeah, it is hacky.... 

@app.route('/index')
@app.route('/')
def index(loggedIn=False):
    # give encrypted cookie if not loggedin
    cookie = request.cookies.get('security_feature')
    if (cookie == "dirty_fried_chicken"):
        # logged in
        resp = make_response(render_template('index.html',
            loggedIn=True, currPage="home"))
    else:
        # not logged in
        insecureCookie = base64.b64encode(crazyEncrypt(
            "This is the credentials pinkFoxOnStereoids:hunter2"))
        # print insecureCookie
        resp = make_response(render_template('index.html', 
            loggedIn=False, currPage="home"))
        resp.set_cookie('security_feature', insecureCookie)

    return resp


@app.route('/login', methods=['POST', 'GET'])
def login():
    name = "pinkFoxOnStereoids"
    
    username = request.form.get('username')
    password = request.form.get('password')
    if (username == name and password == "hunter2"):
        newCookie="dirty_fried_chicken"
        resp = make_response(render_template('loggedInFlag.html', name=username))
        resp.set_cookie('security_feature', newCookie)
    elif (username and password):
        error = "invalid username/password"
        resp = make_response(render_template('login.html',
            error=error, currPage="login"))
    else:
        resp = make_response(render_template('login.html',
            currPage="login"))
    return resp

@app.route('/restricted')
def restricted(loggedIn=None):
    cookie = request.cookies.get('security_feature')
    if (cookie != "dirty_fried_chicken"):
        #redirect to index - better way?
        error = "You are not logged in."
        return render_template('index.html', error=error, currPage="home")

    # Check whether user agent is correct
    agent = request.user_agent.string
    if (agent == "SecTalks"):
        #redirect to flag
        return render_template('restricted.html', loggedIn=True,
            currPage="restricted")

    # if not return hints
    return render_template('hints.html', loggedIn=True)

@app.route('/businessexcellence')
def businessExcellence(loggedIn=None):
    cookie = request.cookies.get('security_feature')
    if (cookie == "dirty_fried_chicken"):
        loggedIn=True

    return render_template('businessExcellence.html',
        loggedIn=loggedIn, currPage="businessexcellence")


@app.route('/logout')
def logout():
    cookie = request.cookies.get('security_feature')
    if (cookie != "dirty_fried_chicken"):
        return render_template('index.html')
    resp = make_response(render_template('index.html', loggedIn=False,
        currPage="home"))
    resp.set_cookie('security_feature', '', expires=0)
    return resp



def crazyEncrypt(plaintext):
    ciphertext = ""
    key = 5
    for character in plaintext:
        # Ignore all non alphabetic characters
        if (not character.islower() and not character.isupper()):
            ciphertext += character
            continue # do not change key
        
        if (character.islower()):
            base = ord('a')
            currChar = ord(character)
            tmpChar = ((currChar-base) + key) % 26
            tmpChar = chr(tmpChar + base)
            ciphertext += tmpChar

        elif (character.isupper()):
            base = ord('A')
            currChar = ord(character)
            tmpChar = ((currChar-base) + key) % 26
            tmpChar = chr(tmpChar + base)
            ciphertext += tmpChar

        if (key == 0):
            key = 5
        else:
            key -= 1
    return ciphertext


def crazyDecrypt(ciphertext):
    plaintext = ""
    key = 5
    for character in ciphertext:
        # Ignore all non alphabetic characters
        if (not character.islower() and not character.isupper()):
            plaintext += character
            continue # do not change key
        
        if (character.islower()):
            base = ord('a')
            currChar = ord(character)
            tmpChar = ((currChar-base) - key + 26) % 26
            tmpChar = chr(tmpChar + base)
            plaintext += tmpChar

        elif (character.isupper()):
            base = ord('A')
            currChar = ord(character)
            tmpChar = ((currChar-base) - key + 26) % 26
            tmpChar = chr(tmpChar + base)
            plaintext += tmpChar

        if (key == 0):
            key = 5
        else:
            key -= 1

    return plaintext
