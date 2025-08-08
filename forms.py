from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length

class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class PostForm(FlaskForm):
    content = TextAreaField('Текст поста', validators=[DataRequired()])
    is_public = BooleanField('Публичный')
    request_only = BooleanField('Скрытый, по запросу')
    tags = StringField('Теги (через запятую)')
    submit = SubmitField('Опубликовать')

class CommentForm(FlaskForm):
    content = TextAreaField('Текст комментария', validators=[DataRequired()])
    submit = SubmitField('Отправить комментарий')
