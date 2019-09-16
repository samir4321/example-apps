from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)


app = Flask(__name__)
# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


NORMAL_USERS = ['bob', 'alice']
USERS = NORMAL_USERS + ['admin']


ADMIN_DATABASE = {
    'bob': 'came in last thursday',
    'alice': "hasnt been seen in a while",
}

USER_DATABASE = {
    'bob': 'bobs stuff',
    'alice': 'alices stuff'
}


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if username not in USERS or password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username)
    resp = jsonify(access_token=access_token)
    return resp, 200


# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    if current_user == 'admin':
        resp = jsonify(msg="welcome admin")
    else:
        resp = jsonify(msg="welcome user")
    return resp, 200


def get_access_token():
    return request.headers.get("Authorization").split("Bearer")[1].strip()


@app.route('/users/all', methods=["GET"])
@jwt_required
def get_all_users():
    current_user = get_jwt_identity()
    if current_user != 'admin':
        resp = jsonify(err='unauthorized')
        return resp, 403
    resp = jsonify(users=USERS)
    return resp, 200


@app.route('/records', methods=['GET'])
@jwt_required
def get_admin_records():
    current_user = get_jwt_identity()
    if current_user != 'admin':
        return jsonify(err='unauthorized'), 403
    admin_db_q()
    return jsonify(records=ADMIN_DATABASE), 200


@app.route('/record', methods=['GET'])
@jwt_required
def user_record():
    current_user = get_jwt_identity()
    user_record = USER_DATABASE.get(current_user)
    user_record_q(current_user)
    resp = jsonify(user_record=user_record)
    return resp, 200

@app.after_request
def after_request(response):
    run_log(request, response)
    return response

def run_log(request, response):
    access_token = ""
    url = request.url
    if request.headers.has_key("Authorization"):
        access_token = request.headers.get("Authorization").split("Bearer")[1].strip()
    status_code = response.status_code
    resp = response.get_json()
    app.logger.info("\n")
    app.logger.debug({"token": access_token, "url": url, "resp": resp, "resp_code": status_code})


def user_record_q(user):
    q = f'SELECT * FROM USER_DATABASE WHERE user={user}'
    nrecords_accessed = 1
    return q, nrecords_accessed


def admin_db_q():
    q = f'SELECT * FROM ADMIN_DATABASE'
    nrecords_accessed = 200
    return q, nrecords_accessed



if __name__ == '__main__':
    import logging
    logging.basicConfig(filename="server.log", level=logging.DEBUG)
    app.run(host='0.0.0.0', port=8080)
