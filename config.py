import os

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "app_fl.sql3")
SECRET_KEY = "thisisthesecretkey"
SECURITY_PASSWORD_SALT = 'lkjsdflkilkjsdlkjndlkk'
