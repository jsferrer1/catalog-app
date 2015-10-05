#Item Catalog App

##Table of Contents

* Introduction
* Pre-Requisites
* Running the Program
* User Guide


##Introduction:

The Item Catalog App is a real-world application that provides a list of items in a variety of categories. It also integrates third party user registration and authentication like Google+ and Facebook. Authenticated users have the ability to post, edit, and delete their own items. Public is only allowed to view the item information.

##Pre-Requisites:

  - Vagrant, Virtual Box
  - Ubuntu 14.04.2 LTS
  - Python 2.7
  - SQLAlchemy 0.8.4
  - SQLite 3.8.2
  - Flask 0.9  
  
  Installation guide: https://www.udacity.com/wiki/ud088/vagrant

##Running the Program:

  1. Download "catalog.zip" and unzip the file into the folder (/vagrant/). 
  
     ```
     $ cd (/vagrant/catalog)
     ```

  2. Make sure that the catalog database is clean and created.
  
     ```
     $ rm catalog.db 
     $ python database_setup.py 
     $ python loaditems.py 
     ```

     Note: If you ran into any error, just repeat the steps again.
     
     ```
     $ rm catalog.db
     $ python database_setup.py     
     $ python loaditems.py      
     ```
     
  3. Authentication
     
     To cater to Google+ sign-in, ensure that the client_secrets.json 
     file exists with a valid client-id, client-secret, etc.
     
     To cater to Facebook login, ensure that the fb_client_secrets.json
     file exists with a valid app_id and app_secret.
     
     
  4. Run the application
  
    ```
     $ python application.py
      * Running on http://0.0.0.0:8000/
      * Restarting with reloader
    ``` 
    
  5. Test the website if it's running 
     - Launch your browser then type the url: http://localhost:8000.
     - The browser should show the Home page containing the Latest Items

##User Guide:

    Refer to Catalog_User_Guide.pdf for more details.
       
-end-