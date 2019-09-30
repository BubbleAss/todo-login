from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (LoginManager, UserMixin, login_user, 
login_required, logout_user, current_user)



app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    todo_items = db.relationship('Todo', backref='user', lazy=True)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200))
    isCompleted = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(),Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired(), Email(message='Invalid E-mail'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(),Length(min=8, max=80)])

class TodoForm(FlaskForm):
    content = StringField('Content', validators=[InputRequired(), Length(max=50)])

class UpdateForm(FlaskForm):
    content = StringField('Content', validators=[InputRequired(), Length(max=50)])




@app.route('/')
def index():
    return render_template('index.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('task_manager'))
        
        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)



@app.route('/signup', methods=['GET', 'POST'] )
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'

    return render_template('signup.html', form=form)



@app.route('/task-manager', methods=['GET', 'POST'])
@login_required
def task_manager():
    form = TodoForm()
    if form.validate_on_submit():
        new_todo = Todo(content=form.content.data, isCompleted=False, user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()

    todo_stuff = Todo.query.filter_by(user_id=current_user.id).all()

    return render_template('task-manager.html', data=todo_stuff, form=form)



@app.route('/task-manager/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    if task_to_delete.user_id != current_user.id:
        return redirect('/task-manager')

    db.session.delete(task_to_delete)
    db.session.commit()
    print('deleted')
    return redirect('/task-manager')

@app.route('/task-manager/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UpdateForm()
    task_to_update = Todo.query.get_or_404(id)

    if task_to_update.user_id != current_user.id:
        return redirect('task-manager')
    
    if form.validate_on_submit():
        task_to_update.content = form.content.data
        db.session.commit()
        print('UPDATED')
        return redirect(url_for('task_manager'))
    else:
        print(form.errors)
    
    form.content.data = task_to_update.content
    return render_template('update.html', form=form, id=id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)