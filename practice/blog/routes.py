from flask import render_template, redirect, url_for, flash, request
from blog import app, db
from blog.forms import RegistrationForm, LoginForm, PostForm, CommentForm
from blog.models import User, Post, Tag, Comment
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('feed'))
        flash('Login failed', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        tags_list = [t.strip() for t in form.tags.data.split(',') if t.strip()]
        tag_objs = []
        for tag_name in tags_list:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
            tag_objs.append(tag)

        post = Post(content=form.content.data, is_public=form.is_public.data,
                    request_only=form.request_only.data, author=current_user)
        post.tags = tag_objs
        db.session.add(post)
        db.session.commit()
        flash('Post created!', 'success')
        return redirect(url_for('index'))
    return render_template('post.html', form=form)

@app.route('/feed')
@login_required
def feed():
    posts = Post.query\
        .filter(Post.author.has(User.id.in_([u.id for u in current_user.subscriptions])))\
        .order_by(Post.date_posted.desc()).all()
    return render_template('feed.html', posts=posts)

@app.route('/subscribe/<int:user_id>', methods=['POST'])
@login_required
def subscribe(user_id):
    user = User.query.get_or_404(user_id)
    if user != current_user and user not in current_user.subscriptions:
        current_user.subscriptions.append(user)
        db.session.commit()
        flash(f'Вы подписались на {user.username}!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(content=form.content.data, post=post, user_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
    return render_template('view_post.html', post=post, form=form)

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        return redirect(url_for('index'))

    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.content = form.content.data
        post.is_public = form.is_public.data
        post.request_only = form.request_only.data
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('post.html', form=form, edit=True)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author == current_user:
        db.session.delete(post)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/tag/<string:tag_name>')
@login_required
def posts_by_tag(tag_name):
    tag = Tag.query.filter_by(name=tag_name).first_or_404()
    return render_template('index.html', posts=tag.posts.order_by(Post.date_posted.desc()))
