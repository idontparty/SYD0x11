from flask import Flask, request, make_response
import string
app = Flask(__name__)

@app.route('/index')
@app.route('/')
def index():
    # give encrypted cookie if not loggedin
    cookie = request.cookies.get('security_feature')
    if (cookie == "dirty_fried_chicken"):
        # logged in
        resp = make_response(render_template('index.html'))
    else:
        # not logged in
        insecureCookie = base64(crazyEncrypt(
            "This is the credentials pinkFoxOnStereoids:hunter2"))
        resp = make_response(render_template('index.html'))
        resp.set_cookie('security_feature', insecureCookie)

    return resp


@app.route('/login')
def login():
    # if credentials are correct, generate
    # dirty_fried_chicken cookie and give flag
    pass 

@app.route('/restricted')
def restricted():
    cookie = request.cookies.get('security_feature')
    if (cookie != "dirty_fried_chicken"):
        #redirect to index - better way?
        return render_template('index.html')

    # Check whether user agent is correct
    agent = request.user_aget.string
    if (agent == "SecTalks"):
        #redirect to flag
        return render_template('hints.html')


    # if not return hints
    return render_template('hints.html')



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