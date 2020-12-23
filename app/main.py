from flask import Flask, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'c1155c6a351e49eba15c00ce577b259e'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    notes = db.relationship('Note', backref='writer', lazy='dynamic')


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(25))
    note_body = db.Column(db.String(100))
    note_writer = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "example@gmail.com"})
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "********"})
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(max=50)], render_kw={"placeholder":  "Password"})
    submit = SubmitField("Login")


class NewNoteForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired(), Length(max=25)], render_kw={"placeholder": "Title"})
    note_body = StringField("Note Body", validators=[InputRequired(), Length(max=100)], render_kw={"placeholder":  "Note Body"})
    submit = SubmitField("Add Note")


@app.route('/home')
@app.route('/')
def home():
    return render_template('index.html', title='Home')


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("view_notes"))
    
        flash("User does not exist, or invalid username or password.")
    return render_template('login.html', title="Login", form=form)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/logout', methods=["GET","POST"])
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))


@app.route('/new-note', methods=['GET','POST'])
@login_required
def new_note():
    form = NewNoteForm()
    if form.validate_on_submit():
        new_note = Note(title=form.title.data, note_body=form.note_body.data, writer=current_user)
        db.session.add(new_note)
        db.session.commit()
        return redirect(url_for('view_notes'))
    return render_template('new_note.html', title='New Note', form=form)


@app.route('/my-notes', methods=['GET','POST'])
@login_required
def view_notes():
    notes = Note.query.filter_by(writer=current_user).all()
    return render_template('my_notes.html', notes=notes, title='My Notes')


@app.route('/delete-note/<int:note_id>', methods=['GET',"POST"])
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('view_notes'))

if __name__ == '__main__':
    app.run(debug=True)