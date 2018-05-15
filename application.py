from flask import Flask, render_template, request, redirect
from flask import url_for, flash, jsonify
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
from flask import session as login_session
import httplib2
import json
import requests
import string
import random
from functools import wraps

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
                open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'CatalogItem'


def pre_login(f):
    """
    To check user is logged in.
    """
    @wraps(f)
    def login_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return login_function


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/logout')
def showLogout():
    if login_session['provider'] == 'google':
        gdisconnect()
        del login_session['gplus_id']
        del login_session['access_token']

    # reset user's information
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']

    return redirect(url_for('showCatalog'))


def addUser(login_session):
    """
    Function to add new User(if needed)
    """
    addUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(addUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Gathers data from Google Sign In API.
    Places data inside a session variable.
    Login with google.
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # access_token = request.data
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
        access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = addUser(login_session)
    login_session['user_id'] = user_id

    return "Logged in Successfully!"


@app.route('/gdisconnect')
def gdisconnect():
    """
    Logout from google.
    """
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps(
            "Current user not connected."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        # reset login information
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps(
            "Failed to revoke token for given user."), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id))

    if 'username' not in login_session:
        return render_template(
            'public_catalog.html', categories=categories, items=items)
    else:
        return render_template(
            'private_catalog.html', categories=categories, items=items)


@app.route('/category/new', methods=['GET', 'POST'])
@pre_login
def newCategory():
    pre_categories = session.query(Category).all()
    if request.method == 'POST':
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserId(login_session['email'])
        newCategory = Category(
            categories=request.form['categories'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("New Category %s successfully created!" % newCategory.categories)
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'newCategory.html', pre_categories=pre_categories)


@app.route(
    '/category/<string:category_categories>/edit', methods=['GET', 'POST'])
@pre_login
def editCategory(category_categories):
    editedCategory = session.query(Category).filter_by(
        categories=category_categories).one()
    if editedCategory.user_id != login_session['user_id']:
        return render_template('notallowed.html')
    if request.method == 'POST':
        if request.form['categories']:
            editedCategory.categories = request.form['categories']
            flash(
                'Category %s successfully edited!' % editedCategory.categories)
            return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'editCategory.html',
            category=editedCategory,
            category_categories=category_categories)


@app.route(
    '/category/<string:category_categories>/delete', methods=['GET', 'POST'])
@pre_login
def deleteCategory(category_categories):
    categoryToDelete = session.query(Category).filter_by(
        categories=category_categories).one()
    if categoryToDelete.user_id != login_session['user_id']:
        return render_template('notallowed.html')
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash(
            'Category %s successfully deleted!' % categoryToDelete.categories)
        return redirect(url_for(
            'showCatalog',
            category_categories=category_categories))
    else:
        return render_template(
            'deleteCategory.html',
            category=categoryToDelete,
            category_categories=category_categories)


@app.route('/category/<string:category_categories>/')
@app.route('/category/<string:category_categories>/items')
def showCategorywithItem(category_categories):
    """
    Show particular category's all items.
    """
    category = session.query(Category).filter_by(
        categories=category_categories).one()
    items = session.query(Item).filter_by(
        category_categories=category_categories).all()
    return render_template(
        'showItemwithCategory.html',
        category=category,
        items=items)


@app.route('/category/item/new', methods=['GET', 'POST'])
@pre_login
def newItem():
    pre_items = session.query(Item).all()
    categories = session.query(Category).all()
    if request.method == 'POST':
        newItem = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_categories=request.form['category'])
        session.add(newItem)
        session.commit()
        flash("New Item %s successfully created!" % newItem.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'newItem.html',
            categories=categories,
            pre_items=pre_items)


@app.route(
    '/category/<string:category_categories>/item/<string:item_name>')
@pre_login
def itemDetail(category_categories, item_name):
    category = session.query(Category).filter_by(
        categories=category_categories).one()
    item = session.query(Item).filter_by(name=item_name).one()
    return render_template('itemDetail.html', category=category, item=item)


@app.route(
    '/category/<string:category_categories>/item/<string:item_name>/edit',
    methods=['GET', 'POST'])
@pre_login
def editItem(category_categories, item_name):
    categories = session.query(Category).all()
    editedItem = session.query(Item).filter_by(name=item_name).one()
    if editedItem.user_id != login_session['user_id']:
        return render_template('notallowed.html')

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_categories = request.form['category']
        session.add(editedItem)
        session.commit()
        flash("Item %s successfully edited!" % editedItem.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'editItem.html', item=editedItem, categories=categories)


@app.route(
    '/category/<string:category_categories>/item/<string:item_name>/delete',
    methods=['GET', 'POST'])
@pre_login
def deleteItem(category_categories, item_name):
    category = session.query(Category).filter_by(
        categories=category_categories).one()
    itemToDelete = session.query(Item).filter_by(name=item_name).one()
    if itemToDelete.user_id != login_session['user_id']:
        return render_template('notallowed.html')
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item %s successfully deleted!" % itemToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'deleteItem.html', item=itemToDelete, category=category)


@app.route('/categories.json')
def showCategoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/items.json')
def showItemsJSON():
    items = session.query(Item).all()
    return jsonify(Items=[i.serialize for i in items])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
