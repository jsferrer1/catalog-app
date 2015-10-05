#!/usr/bin/env python

"""File name: application.py 
   The Catalog App provides a list of items in a variety of categories. It also integrates third party user registration and authentication like Google+ and Facebook. Authenticated users have the ability to post, edit, and delete their own items. Public is only allowed to view the item information.
"""

__author__      = "Jerry Ferrer"
__copyright__   = "Copyright (c) 2015"

# Use flask as the web framework
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash

# Database functions
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
from flask import session as login_session
import random, string

# OAuth authentication
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response, Response
import requests

# File upload
import os
from flask import send_from_directory
from werkzeug import secure_filename

# Cross-site request forgery
from flask.ext.seasurf import SeaSurf

# JSON and XML support
import json
import dicttoxml

# logging
import logging
logging.getLogger().setLevel(logging.DEBUG)

# Initialize the flask framework & the CRSF capability
app = Flask(__name__)
csrf = SeaSurf(app)

CATALOG_PATH = "/var/www/catalog/catalog/"
CLIENT_SECRETS = CATALOG_PATH + "client_secrets.json"
FB_CLIENT_SECRETS = CATALOG_PATH + "fb_client_secrets.json"
CLIENT_ID = json.loads(open(CLIENT_SECRETS, 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
logging.info("create_engine: postgresql: -d catalog -h localhost -U catalog")
engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# This is the path to the upload directory
app.config['UPLOAD_FOLDER'] = 'static/img/'

# These are the extension that we are accepting to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    
    # retrieve the google client_id and facebook app_id
    client_id = json.loads(open(CLIENT_SECRETS,'r').read())['web']['client_id']
    app_id = json.loads(open(FB_CLIENT_SECRETS,'r').read())['web']['app_id']
    
    print "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, client_id=client_id, app_id=app_id)

# Connect to facebook
@csrf.exempt     
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    #print "access token received %s " % access_token

    # Exchange client token for long-lived server-side token with
    # GET /oauth/access_token...
    app_id = json.loads(open(FB_CLIENT_SECRETS, 'r').read())['web']['app_id']
    app_secret = json.loads(
        open(FB_CLIENT_SECRETS, 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.2/me"
    # strip expire tag from access token - usually two months
    token = result.split("&")[0]

    fields = 'fields=name,email'
    url = 'https://graph.facebook.com/v2.2/me?%s&%s' % (fields, token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    #print "url sent for API access:%s"% url
    #print "API JSON result: %s" % result
    
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
        
    login_session['user_id'] = user_id
    print "fbconnect: verified login_session [%s]" %str(login_session)

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

# Disconnect from facebook
@csrf.exempt     
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# Connect to google+
@csrf.exempt     
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(CLIENT_SECRETS, scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'    
    print "gconnect: verified login_session [%s]" %str(login_session)
    
    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
        
    login_session['user_id'] = user_id
    
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output    

# Disconnect from google+    
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        if 'credentials' in login_session:
            del login_session['credentials']
        if 'gplus_id' in login_session:
            del login_session['gplus_id']
        if 'username' in login_session['username']:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Show the catalog items in JSON format        
@app.route('/catalog/JSON')
def catalogJSON():
    catalog_json = generateJSON()
    fp = open('static/catalog.json', 'w')
    json.dump(catalog_json, fp, sort_keys=False, indent=2)
    fp.close()
    
    # redirect to the jsonified catalog file
    return redirect('/static/catalog.json')

# Convert the JSON format to XML format
@app.route('/catalog/XML')
def catalogXML():
    catalog_json = generateJSON()
    catalog_xml = dicttoxml.dicttoxml(catalog_json, attr_type=False, root=False)
    fp = open('static/catalog.xml', 'w')
    fp.write(catalog_xml)
    fp.close()
    
    # redirect to the xml catalog file
    return redirect('/static/catalog.xml')

# Generate the catalog items in JSON format        
def generateJSON():
    categories = session.query(Category).all()
    catalog = [c.serialize for c in categories]   
    
    # process the catalog items
    j = 0
    for c in catalog:
      items = []
      items = [i.serialize for i in c['Item']]
      if items != []:
        catalog[j]['Item'] = items
      else:
        del catalog[j]['Item']
      j = j + 1
    
    # finalize the json with Category
    catalog_json = {'Category':{}}
    catalog_json['Category'] = catalog
    return catalog_json
    
    
# Show the latest catalog items
@app.route('/')
@app.route('/catalog/')
def showCatalog():
  categories = session.query(Category).all()
  items = session.query(CategoryItem,Category).join(CategoryItem.category).order_by(desc(CategoryItem.id)).all()
  if 'username' not in login_session:
    return render_template('publiccatalog.html', categories=categories, items=items)
  else:
    user_id = login_session['user_id']
    return render_template('catalog.html', categories=categories, items=items, user_id=user_id)

# Show the items from a particular category
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items/')
def showItems(category_id):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id = category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(CategoryItem).filter_by(cat_id = category_id).all()
    if 'username' not in login_session:
        return render_template('publicitems.html', items=items, category=category, creator=creator, categories=categories)
    else:
        user_id = login_session['user_id']
        return render_template('items.html', items=items, category=category, creator=creator, categories=categories, user_id=user_id)

     
# Create a new item on a particular category
@app.route('/item/new/',methods=['GET','POST'])
def newCategoryItem():
  # Protect pages from the internet/public
  if 'username' not in login_session:
    return redirect('/login')
    
  user_id = login_session['user_id']
  categories = session.query(Category).all()
  
  if request.method == 'POST':
      # Save the uploaded photo first, else use a default photo
      if request.files['file']:
        filename = upload(request)
      else: 
        filename = os.path.join("/", app.config['UPLOAD_FOLDER'], "upload.jpg")
        
      # Create a new item
      category_id = request.form['category']
      category = session.query(Category).filter_by(id=category_id).one()
      newItem = CategoryItem(name = request.form['name'], 
                             description = request.form['description'], 
                             cat_id = category_id,
                             user_id = user_id,
                             picture = filename)
      session.add(newItem)
      session.commit()
      flash('New Item %s Successfully Created' % (newItem.name))
      return redirect(url_for('showItems', category_id=category_id))
  else:
      return render_template('newitem.html', categories=categories)

     
# Edit an item in  particular category
@app.route('/category/<int:category_id>/item/<int:item_id>/edit', methods=['GET','POST'])
def editCategoryItem(category_id, item_id):
    # Protect pages from the internet/public
    if 'username' not in login_session:
        return redirect('/login')
    
    editedItem = session.query(CategoryItem).filter_by(id = item_id).one()
    category = session.query(Category).filter_by(id = category_id).one()
    
    # Display all the available categories
    user_id = login_session['user_id']
    categories = session.query(Category).all()

    # Prevent other users from adding items to the category
    if editedItem.user_id != login_session['user_id']:
      return "<script>function alertUser() {alert('You are not authorized to edit this item from this category. Please create your own menu item.');window.location.href='/catalog';}</script><body onload='alertUser()''>"

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.files['file']:
            editedItem.picture = upload(request)
        session.add(editedItem)
        session.commit() 
        flash('Item Successfully Edited')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('edititem.html', category_id=category_id, item_id=item_id, item=editedItem, categories=categories)
     
# Delete an item from particular category
@app.route('/category/<int:category_id>/item/<int:item_id>/delete', methods=['GET','POST'])
def deleteCategoryItem(category_id, item_id):
    # Protect pages from the internet/public
    if 'username' not in login_session:
        return redirect('/login')
    
    category = session.query(Category).filter_by(id = category_id).one()
    itemToDelete = session.query(CategoryItem).filter_by(id = item_id).one() 
    
    # Prevent other users from deleting items of other users
    if itemToDelete.user_id != login_session['user_id']:
      return "<script>function alertUser() {alert('You are not authorized to edit this item from this category. Please create your own menu item.');window.location.href='/catalog';}</script><body onload='alertUser()''>"

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=itemToDelete)
     
# Get user id using the email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None
        
# Get user information base on user ID
def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user
        
# Create a new user based on the login session information
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'], 
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            
        # Verify if login information exists before delete
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']
        if 'user_id' in login_session: 
            del login_session['user_id']
        if 'provider' in login_session:
            del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))
    
# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

# Upload a given file to the /static/img folder
def upload(request):
    # Get the name of the uploaded file
    file = request.files['file']
    file.filename = file.filename.lower()
    
    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        # Make the filename safe, remove unsupported chars
        filename = secure_filename(file.filename)
        
        # Move the file form the temporal folder to
        # the upload folder we setup
        file.save(os.path.join(CATALOG_PATH, app.config['UPLOAD_FOLDER'], filename))
        
        # return the home url of the uploaded file
        return os.path.join("/", app.config['UPLOAD_FOLDER'], filename)

#main execution
if __name__ == '__main__':
  app.run()
