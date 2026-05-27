from app import app
from models import db

with app.app_context():
    db.create_all()
    print("Base de datos creada con éxito.")
# This script initializes the database by creating all tables defined in the models.
# It should be run once to set up the database schema.