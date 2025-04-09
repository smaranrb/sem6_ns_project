from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS
from models.user import db, User
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"

# DB & Login
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Blueprints will go here later
# from routes.auth import auth_bp
# app.register_blueprint(auth_bp)

# CLI command to create DB
@app.cli.command("create-db")
def create_db():
    db.create_all()
    print("✅ Database tables created!")

from routes.auth import auth_bp
app.register_blueprint(auth_bp)

from routes.attack import attack_bp
app.register_blueprint(attack_bp)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

