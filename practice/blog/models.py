from datetime import datetime
from blog import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

subscriptions = db.Table('subscriptions',
    db.Column('subscriber_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('subscribed_id', db.Integer, db.ForeignKey('user.id'))
)

tags = db.Table('tags',
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    subscriptions = db.relationship('User',
        secondary=subscriptions,
        primaryjoin=(subscriptions.c.subscriber_id == id),
        secondaryjoin=(subscriptions.c.subscribed_id == id),
        backref=db.backref('subscribers', lazy='dynamic'),
        lazy='dynamic'
    )

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=True)
    request_only = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tags = db.relationship('Tag', secondary=tags, backref=db.backref('posts', lazy='dynamic'))
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref='comments')
