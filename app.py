from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import string, random, os
import qrcode
from qrcode.image.pil import PilImage

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shortener.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'yoursecretkey'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'qr')

db = SQLAlchemy(app)

@app.context_processor
def inject_datetime():
    return dict(datetime=datetime)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    urls = db.relationship('Url', backref='owner', lazy=True)

class Url(db.Model):
    __tablename__ = 'url'
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(512), nullable=False)
    short = db.Column(db.String(10), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    clicks = db.relationship('Click', backref='url', lazy=True)

class Click(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def generate_short_slug(length=6):
    characters = string.ascii_letters + string.digits
    while True:
        short = ''.join(random.choices(characters, k=length))
        if not Url.query.filter_by(short=short).first():
            return short

def create_qr_code(slug):
    full_url = request.host_url.rstrip('/') + '/' + slug
    qr = qrcode.make(full_url, image_factory=PilImage)
    output_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f'{slug}.png')
    qr.save(path)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash('Login required to view dashboard.')
        return redirect(url_for('login'))

    short_url = None

    if request.method == 'POST':
        long_url = request.form['long_url']
        custom_slug = request.form.get('custom_slug')

        if custom_slug and Url.query.filter_by(short=custom_slug).first():
            flash('Custom slug already taken. Try another.', 'error')
            return redirect(url_for('dashboard'))

        short = custom_slug if custom_slug else generate_short_slug()
        new_url = Url(original_url=long_url, short=short, user_id=session['user_id'])
        db.session.add(new_url)
        db.session.commit()
        create_qr_code(short)
        short_url = short
        flash(f'Short URL created: {request.host_url}{short_url}', 'success')

    urls = Url.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', urls=urls, short_url=short_url)

@app.route('/<short>')
def redirect_short_url(short):
    url = Url.query.filter_by(short=short).first_or_404()
    click = Click(url_id=url.id)
    db.session.add(click)
    db.session.commit()
    return redirect(url.original_url)

@app.route('/stats-data/<short>')
def stats_data(short):
    url = Url.query.filter_by(short=short).first_or_404()
    clicks = Click.query.filter_by(url_id=url.id).order_by(Click.timestamp).all()
    daily_clicks = {}
    for click in clicks:
        day = click.timestamp.strftime('%Y-%m-%d')
        daily_clicks[day] = daily_clicks.get(day, 0) + 1
    dates = sorted(daily_clicks.keys())
    counts = [daily_clicks[date] for date in dates]
    return jsonify({"dates": dates, "counts": counts})

@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return "Access denied", 403
    urls = Url.query.all()
    return render_template('admin.html', urls=urls)

@app.route('/admin/delete/<int:url_id>', methods=['POST'])
def delete_url(url_id):
    if not session.get('is_admin'):
        return "Access denied", 403
    url = Url.query.get_or_404(url_id)
    db.session.delete(url)
    db.session.commit()
    flash('URL deleted successfully.')
    return redirect(url_for('admin'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash('Logged in successfully!', 'success')

            # Redirect based on role
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('dashboard'))

        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_pw = generate_password_hash('admin123')
            admin_user = User(username='admin', password=hashed_pw, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)
