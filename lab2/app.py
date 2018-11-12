from flask import Flask, render_template, flash, redirect, url_for, session, send_from_directory
from forms import RegistrationForm, LoginForm, UploadForm
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug import secure_filename
from spell_checker import spellchecker
import os
import base64
import json
from werkzeug.datastructures import FileStorage
from io import BytesIO
from ast import literal_eval
import shutil  # used later to DELETE a folder from the storage

app = Flask(__name__)
# key to encrypt cookie data
app.config['SECRET_KEY'] = '467884264a98e0ab2832dc708e4b147e690ef88deac7b3f0a2c858153c6c32a3'
# modify as necessary
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/appsec'
# UPLOAD_FOLDER is directory where user uploads will be stored
# unique to my evironment, modify as necessary
app.config['UPLOAD_FOLDER'] = '/home/user/AppSec_WebApp/uploads/'
# should be of the form "<path_to_folder_containing_app.py>/uploads/"
app.config['MAX_CONTENT_LENGTH'] = 1 * \
    1024 * 1024  # allow .txt file size of 1mb
db = SQLAlchemy(app)


class User(db.Model):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    __tablename__ = 'User'
    username = db.Column('username', db.Unicode, primary_key=True)
    password = db.Column('password', db.Unicode)


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = sha256_crypt.hash(form.password.data)
        if not User.query.filter_by(username=username).first():
            user = User(username, password)
            db.session.add(user)
            db.session.commit()
            flash(f'Registration Successful')
            return redirect(url_for('home'))
        flash("That username is taken.")
    return render_template('register.html', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        entry = User.query.filter_by(username=username).first()
        if entry and sha256_crypt.verify(password, entry.password):
            session['username'] = username
            flash(f'Login Successful')
            return redirect(url_for('home'))
        flash('Information incorrect.')
    return render_template('login.html', form=form)


@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


@app.route("/uploads/")
def uploads():
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    if not os.path.exists(file_path):
        flash("You haven't uploaded any files yet.")
        return render_template('uploads.html')
    uploaded = []
    errors = {}
    for items in os.listdir(file_path):
        if os.path.isdir(file_path + '/' + items):  # avoid adding errors subdirectory
            continue
        filename = session['username'] + '/' + items
        sent = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        sent.direct_passthrough = False
        decoded = base64.b64decode(sent.data)
        uploaded.append((items, decoded.decode('ascii')))
        if os.path.exists(file_path + '/' + 'errors/' + items):
            errors_sent = send_from_directory(
                app.config['UPLOAD_FOLDER'], session['username'] + '/' + 'errors/' + items)
            errors_sent.direct_passthrough = False
            errors[items] = literal_eval(errors_sent.data.decode('ascii'))
    return render_template('uploads.html', uploads=uploaded, errors=errors)

# not really needed
# @app.route('/uploads/<filename>')
# def uploaded_file(filename):
#     filename = session['username'] + '/' + filename
#     sent = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
#     sent.direct_passthrough = False
#     decoded = base64.b64decode(sent.data)
#     return decoded


@app.route("/spellcheck", methods=['GET', 'POST'])
def spellcheck():
    form = UploadForm()
    if form.validate_on_submit():
        f = form.upload.data
        filename = secure_filename(f.filename)
        errors = spellchecker(filename)
        encoded = base64.b64encode(f.read())
        encoded = FileStorage(BytesIO(encoded), filename)
        file_path = os.path.join(
            app.config['UPLOAD_FOLDER'], session['username'])
        errors_file_path = os.path.join(
            app.config['UPLOAD_FOLDER'], session['username'], 'errors')
        if os.path.exists(file_path):
            files = os.walk(file_path).__next__()[2]
            if len(files) >= 5:
                # this will DELETE the user's folder from storage
                shutil.rmtree(file_path)
                flash('Storage limit exceeded. Your storage has reset.')
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        if not os.path.exists(errors_file_path):
            os.makedirs(errors_file_path)
        encoded.save(os.path.join(file_path, filename))  # save file
        with open(errors_file_path + '/' + filename, 'w') as errors_file:
            errors_file.write(json.dumps(errors))
        return redirect(url_for('uploads'))

    return render_template('spellcheck.html', form=form)


if __name__ == '__main__':
    # app.run(debug=True)
    app.run()
