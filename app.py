

import os
if not os.path.exists('instance'):
    os.makedirs('instance')
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from email_validator import validate_email, EmailNotValidError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room

app = Flask("NrzCommunication", instance_relative_config=True)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'users.db')}"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, async_mode='threading')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    ban_status = db.Column(db.String(20), default=None)  # None, 'temp', 'perm'
    ban_reason = db.Column(db.String(255), default=None)
    ban_until = db.Column(db.DateTime, default=None)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Adresse mail invalide.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Nom d\'utilisateur ou email déjà utilisé.', 'danger')
            return render_template('register.html')
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Compte créé avec succès. Connectez-vous.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=username, email=email).first()
        if user and check_password_hash(user.password, password):
            # Vérifie le statut de bannissement
            from datetime import datetime
            if user.ban_status == 'perm':
                flash("Vous avez été banni définitivement. Raison : " + (user.ban_reason or "aucune"), 'danger')
                return render_template('login.html')
            elif user.ban_status == 'temp':
                if user.ban_until and user.ban_until > datetime.utcnow():
                    flash(f"Vous êtes temporairement banni jusqu'au {user.ban_until.strftime('%d/%m/%Y %H:%M')}. Raison : " + (user.ban_reason or "aucune"), 'danger')
                    return render_template('login.html')
                else:
                    # Débannir automatiquement si la date est passée
                    user.ban_status = None
                    user.ban_reason = None
                    user.ban_until = None
                    db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Identifiants invalides.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Accès réservé à l'administrateur.", 'danger')
        return redirect(url_for('index'))
    from datetime import datetime, timedelta
    users = User.query.filter(User.id != current_user.id).all()
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        reason = request.form.get('reason')
        ban_time = request.form.get('ban_time')
        user = User.query.get(int(user_id))
        if action == 'ban_temp':
            try:
                hours = int(ban_time)
                user.ban_status = 'temp'
                user.ban_reason = reason
                user.ban_until = datetime.utcnow() + timedelta(hours=hours)
                db.session.commit()
                flash(f"{user.username} banni temporairement.", 'success')
            except Exception:
                flash("Erreur lors du bannissement temporaire.", 'danger')
        elif action == 'ban_perm':
            user.ban_status = 'perm'
            user.ban_reason = reason
            user.ban_until = None
            db.session.commit()
            flash(f"{user.username} banni définitivement.", 'success')
        elif action == 'unban':
            user.ban_status = None
            user.ban_reason = None
            user.ban_until = None
            db.session.commit()
            flash(f"{user.username} débanni.", 'success')
        return redirect(url_for('admin_panel'))
    return render_template('admin.html', users=users)

@app.route('/')
@login_required
def index():
    messages = Message.query.order_by(Message.timestamp.asc()).limit(100).all()
    return render_template('index.html', username=current_user.username, messages=messages)

# API pour charger les messages (pour AJAX)
@app.route('/messages')
@login_required
def get_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).limit(100).all()
    return jsonify([
        {"username": m.username, "content": m.content, "timestamp": m.timestamp.strftime('%d/%m/%Y %H:%M')} for m in messages
    ])

# SocketIO event pour envoyer un message
@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return
    content = data.get('content', '').strip()
    if not content:
        return
    msg = Message(username=current_user.username, content=content)
    db.session.add(msg)
    db.session.commit()
    emit('receive_message', {
        'username': current_user.username,
        'content': content,
        'timestamp': msg.timestamp.strftime('%d/%m/%Y %H:%M')
    }, broadcast=True)



if __name__ == '__main__':
    # Création des tables et du compte admin par défaut
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            admin = User(
                username='NrzM1001',
                email='esteban.coulaud01@gmail.com',
                password=generate_password_hash('13472001@'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
