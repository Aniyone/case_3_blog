from flask import render_template, redirect, url_for, flash, request
from blog import app, db
from blog.forms import RegistrationForm, LoginForm, PostForm, CommentForm
from blog.models import User, Post, Tag, Comment, AccessRequest, PostAccess
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def index():
    posts = Post.query\
        .order_by(Post.date_posted.desc()).all()
    visible_posts = []
    for post in posts:
        post.access_granted = False
        if post.is_public or (current_user.is_authenticated and post.user_id == current_user.id):
            post.access_granted = True
        elif current_user.is_authenticated and PostAccess.query.filter_by(post_id=post.id, user_id=current_user.id).first():
            post.access_granted = True
        visible_posts.append(post)
    return render_template('index.html', posts=visible_posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Аккаунт успешно создан!', 'success')
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
        flash('Неправильные данные пользователя.', 'danger')
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
        flash('Пост был успешно опубликован!', 'success')
        return redirect(url_for('index'))
    return render_template('post.html', form=form)

@app.route('/feed')
@login_required
def feed():
    posts = Post.query\
        .filter(Post.author.has(User.id.in_([u.id for u in current_user.subscriptions])))\
        .order_by(Post.date_posted.desc()).all()
    visible_posts = []
    for post in posts:
        post.access_granted = False
        if post.is_public or post.user_id == current_user.id:
            post.access_granted = True
        elif PostAccess.query.filter_by(post_id=post.id, user_id=current_user.id).first():
            post.access_granted = True
        visible_posts.append(post)
    return render_template('feed.html', posts=visible_posts)


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
    access_granted = False
    if post.is_public or post.author == current_user:
        access_granted = True
    elif PostAccess.query.filter_by(post_id=post.id, user_id=current_user.id).first():
        access_granted = True
    form = CommentForm()
    if access_granted and form.validate_on_submit():
        comment = Comment(content=form.content.data, post=post, user_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('view_post', post_id=post.id))
    return render_template('view_post.html', post=post, form=form, access_granted=access_granted)


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

@app.route('/request_access/<int:post_id>', methods=['POST'])
@login_required
def request_access(post_id):
    post = Post.query.get_or_404(post_id)
    existing = AccessRequest.query.filter_by(post_id=post.id, requester_id=current_user.id).first()
    if existing:
        flash("Запрос уже отправлен.", "info")
    else:
        new_request = AccessRequest(post=post, requester=current_user)
        db.session.add(new_request)
        db.session.commit()
        flash("Запрос отправлен автору поста.", "success")
    return redirect(url_for('feed'))

@app.route('/access-requests')
@login_required
def view_access_requests():
    requests = AccessRequest.query \
        .join(Post) \
        .filter(Post.user_id == current_user.id) \
        .order_by(AccessRequest.timestamp.desc()) \
        .all()
    return render_template('access_requests.html', requests=requests)

@app.route('/grant-access/<int:request_id>', methods=['POST'])
@login_required
def grant_access(request_id):
    access_request = AccessRequest.query.get_or_404(request_id)
    post = access_request.post
    username = access_request.requester.username
    access = PostAccess(post_id=post.id, user_id=access_request.requester.id)
    db.session.add(access)
    db.session.delete(access_request)
    db.session.commit()
    flash(f"Доступ к посту предоставлен пользователю {username}.", "success")
    return redirect(url_for('view_access_requests'))
