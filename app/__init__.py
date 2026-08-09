"""app/__init__.py — Application factory"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(config_object="config.Config"):
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    app.config.from_object(config_object)

    db.init_app(app)

    with app.app_context():
        from app import models  # noqa: F401 — register models
        db.create_all()

    from app.routes import bp
    app.register_blueprint(bp)

    return app
