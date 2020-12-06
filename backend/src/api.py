import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()

#Routes

@app.route('/drinks')
def get_drinks():
    drinks=Drink.query.all()
    return jsonify({
        'success':True,
        'drinks':[drink.short() for drink in drinks]
    })

@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    drinks=Drink.query.all()
    return jsonify({
        'success':True,
        'drinks':[drink.long() for drink in drinks]
    })

@app.route('/drinks',methods=['POST'])
@requires_auth('post:drinks')
def post_drinks(payload):
    jsonRequest=request.get_json()
    title=jsonRequest.get('title','')
    recipe=jsonRequest.get('recipe',[])
    recipe=json.dumps(recipe)
    drink=Drink(title=title,recipe=recipe)
    drink.insert()
    return jsonify({
        "success":True,
        "drinks": [drink.long()]
    })

@app.route('/drinks/<int:drink_id>',methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drink(payload,drink_id):
    drink=Drink.query.filter_by(id=drink_id).one_or_none()
    if not drink:
        abort(404,description='can not find drink with this id')
    drink.title=request.get_json().get('title',drink.title)
    drink.recipe=json.dumps(request.get_json().get('recipe',json.loads(drink.recipe)))
    drink.update()
    return jsonify({
        "success":True,
        "drinks":[drink.long()]
    })

@app.route('/drinks/<int:drink_id>',methods=['delete'])
@requires_auth('delete:drinks')
def delete_drink(payload,drink_id):
    drink=Drink.query.filter_by(id=drink_id).one_or_none()
    if not drink:
        abort(404,description='can not find drink with this id')
    drink.delete()
    return jsonify({
        "success":True,
        "delete": drink_id
    })

## Error Handling

@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
                    "success": False, 
                    "error": 422,
                    "message": "unprocessable"
                    }), 422


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "success":False,
        "error":404,
        "message": str(e)
    }), 404

@app.errorhandler(AuthError)
def auth_error(e):
    return jsonify({
        "success":False,
        "error":e.status_code,
        "message": e.error.get('code')+": "+e.error.get('description')
    }), e.status_code
