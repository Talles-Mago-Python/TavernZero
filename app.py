import os
from sqlalchemy import func
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#Filtro de Tempo atras
def time_ago(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    seconds = diff.total_seconds()
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    weeks = days // 7
    months = days // 30
    years = days // 365

    if years > 0:
        return f"{int(years)} ano(s) atrás" if years > 1 else "1 ano atrás"
    elif months > 0:
        return f"{int(months)} mês(es) atrás" if months > 1 else "1 mês atrás"
    elif weeks > 0:
        return f"{int(weeks)} semana(s) atrás" if weeks > 1 else "1 semana atrás"
    elif days > 0:
        return f"{int(days)} dia(s) atrás" if days > 1 else "1 dia atrás"
    elif hours > 0:
        return f"{int(hours)} hora(s) atrás" if hours > 1 else "1 hora atrás"
    elif minutes > 0:
        return f"{int(minutes)} minuto(s) atrás" if minutes > 1 else "1 minuto atrás"
    else:
        return "agora mesmo"
# Filtro para formatar datas
def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    """Filtro que mostra 'há x tempo' para eventos recentes"""
    if value is None:
        return ""
    
    now = datetime.utcnow()
    diff = now - value
    
    if diff.days == 0:
        seconds = diff.seconds
        if seconds < 60:
            return "agora mesmo"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"há {minutes} minuto{'s' if minutes > 1 else ''}"
        else:
            hours = seconds // 3600
            return f"há {hours} hora{'s' if hours > 1 else ''}"
    elif diff.days == 1:
        return "ontem"
    elif diff.days < 7:
        return f"há {diff.days} dia{'s' if diff.days > 1 else ''}"
    else:
        return value.strftime(format)

# filtros no Jinja2
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['time_ago'] = time_ago
# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ========== MODELS ==========
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_picture = db.Column(db.String(100))
    bio = db.Column(db.Text)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    groups = db.relationship('GroupMember', backref='user', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='author', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    invite_token = db.Column(db.String(100), unique=True, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    members = db.relationship('GroupMember', backref='group', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='group', lazy=True, cascade='all, delete-orphan')
    documents = db.relationship('GroupDocument', backref='group', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Group {self.name}>'

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_muted = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<GroupMember user:{self.user_id} group:{self.group_id}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    file_path = db.Column(db.String(100))
    message_type = db.Column(db.String(20), default='text')  # 'text', 'image', 'file', 'dice'
    edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime)

    def __repr__(self):
        return f'<Message {self.id} by {self.user_id}>'

class GroupDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    original_name = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(20))
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='documents')

    def __repr__(self):
        return f'<GroupDocument {self.original_name}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    link = db.Column(db.String(200))

    def __repr__(self):
        return f'<Notification {self.id} for {self.user_id}>'

# ========== FUNÇÕES DE AJUDA ==========
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(f):
    @wraps(f)
    def decorated_function(group_id, *args, **kwargs):
        member = GroupMember.query.filter_by(
            user_id=current_user.id,
            group_id=group_id,
            is_admin=True
        ).first()
        if not member:
            flash('Apenas administradores podem acessar esta página', 'error')
            return redirect(url_for('group_chat', group_id=group_id))
        return f(group_id, *args, **kwargs)
    return decorated_function

def create_notification(user_id, message, link=None):
    notification = Notification(
        user_id=user_id,
        message=message,
        link=link
    )
    db.session.add(notification)
    db.session.commit()

# ========== ROUTES ==========
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Atualiza último acesso do usuário
    current_user.last_seen = datetime.utcnow()
    db.session.commit()

    # Busca grupos do usuário com contagem de mensagens não lidas
    user_groups = db.session.query(Group).join(
        GroupMember,
        GroupMember.group_id == Group.id
    ).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.is_banned == False
    ).all()

    # Calcula mensagens não lidas para cada grupo
    for group in user_groups:
        last_seen = current_user.last_seen or datetime.utcnow()
        group.unread_count = db.session.query(Message).filter(
            Message.group_id == group.id,
            Message.timestamp > last_seen,
            Message.user_id != current_user.id
        ).count()

    # Conta notificações não lidas
    unread_notifications = db.session.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).count()

    # Atividades recentes
    recent_activities = []
    recent_messages = db.session.query(Message).join(
        GroupMember,
        GroupMember.group_id == Message.group_id
    ).filter(
        GroupMember.user_id == current_user.id,
        Message.timestamp > datetime.utcnow() - timedelta(days=7),
        Message.user_id != current_user.id
    ).order_by(Message.timestamp.desc()).limit(5).all()

    for msg in recent_messages:
        recent_activities.append({
            'type': 'message',
            'description': f'Nova mensagem em {msg.group.name}',
            'timestamp': msg.timestamp,
            'link': url_for('group_chat', group_id=msg.group_id)
        })

    # Grupos sugeridos
    suggested_groups = db.session.query(Group).filter(
        Group.is_public == True,
        ~Group.members.any(GroupMember.user_id == current_user.id)
    ).order_by(func.random()).limit(3).all()

    return render_template('dashboard.html',
                         groups=user_groups,
                         unread_count=unread_notifications,  # Corrigido aqui
                         recent_activities=recent_activities,
                         suggested_groups=suggested_groups,
                         group_id=id,)
@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        
        new_group = Group(
            name=name,
            description=description,
            creator_id=current_user.id
        )
        db.session.add(new_group)
        db.session.commit()
        
        # Tornar criador admin
        new_member = GroupMember(
            user_id=current_user.id,
            group_id=new_group.id,
            is_admin=True
        )
        db.session.add(new_member)
        db.session.commit()
        
        flash('Grupo criado com sucesso!', 'success')
        return redirect(url_for('group_chat', group_id=new_group.id))
    
    return render_template('create_group.html')

@app.route('/notifications')
@login_required
def notifications():
    # Mark all as read when visiting notifications page
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()

    user_notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).limit(50).all()

    return render_template('notifications.html', notifications=user_notifications)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    
    if not query:
        return render_template('search.html', results=[], query='')
    
    # Search groups
    group_results = Group.query.filter(
        (Group.name.ilike(f'%{query}%') | 
        (Group.description.ilike(f'%{query}%')),
        Group.is_public == True
    ).limit(10).all())
    
    # Search users
    user_results = User.query.filter(
        (User.username.ilike(f'%{query}%')) |
        (User.bio.ilike(f'%{query}%'))
    ).limit(10).all()
    
    return render_template('search.html', 
                         group_results=group_results,
                         user_results=user_results,
                         query=query)

# ========== GROUP ROUTES ==========
@app.route('/group/<int:group_id>/update_settings', methods=['POST'])
@login_required
@admin_required
def update_group_settings(group_id):
    group = Group.query.get_or_404(group_id)
    
    group.name = request.form.get('name', group.name)
    group.description = request.form.get('description', group.description)
    group.is_public = 'is_public' in request.form
    
    db.session.commit()
    
    flash('Configurações do grupo atualizadas com sucesso!', 'success')
    return redirect(url_for('manage_group', group_id=group_id))
@app.route('/group/<int:group_id>/join')
@app.route('/group/<int:group_id>/join/<token>')
@login_required
def join_group(group_id, token=None):
    group = Group.query.get_or_404(group_id)
    
    # Se não houver token, verifique se o grupo é público
    if not token and not group.is_public:
        flash('Este grupo é privado e requer um convite', 'error')
        return redirect(url_for('dashboard'))
    
    # Verifique se o token é válido (se fornecido)
    if token and (not group.invite_token or group.invite_token != token):
        flash('Link de convite inválido ou expirado', 'error')
        return redirect(url_for('dashboard'))

    # Check if user is already in the group
    existing_member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()
    
    if existing_member:
        flash('Você já é membro deste grupo', 'warning')
        return redirect(url_for('group_chat', group_id=group_id))
    
    # Add user to group
    new_member = GroupMember(
        user_id=current_user.id,
        group_id=group_id
    )
    db.session.add(new_member)
    db.session.commit()
    
    flash(f'Você entrou no grupo {group.name}!', 'success')
    return redirect(url_for('group_chat', group_id=group_id))
@app.route('/group/<int:group_id>/reset_invite', methods=['POST'])
@login_required
@admin_required
def reset_invite(group_id):
    group = Group.query.get_or_404(group_id)
    group.invite_token = generate_random_token()
    db.session.commit()
    
    flash('Link de convite resetado com sucesso!', 'success')
    return redirect(url_for('manage_group', group_id=group_id))

# Helper function (add this somewhere in your code)
def generate_random_token(length=32):
    import secrets
    return secrets.token_urlsafe(length)
@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()
    
    if not member or member.is_banned:
        flash('Você não tem acesso a este grupo', 'error')
        return redirect(url_for('dashboard'))
    
    messages = Message.query.filter_by(group_id=group_id)\
        .order_by(Message.timestamp.asc()).limit(200).all()
    
    documents = GroupDocument.query.filter_by(group_id=group_id)\
        .order_by(GroupDocument.uploaded_at.desc()).limit(10).all()
    
    return render_template('group_chat.html', 
                         group=group,
                         messages=messages,
                         documents=documents,
                         is_admin=member.is_admin)

@app.route('/group/<int:group_id>/manage', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_group(group_id):
    group = Group.query.get_or_404(group_id)
    members = GroupMember.query.filter_by(group_id=group_id)\
        .order_by(GroupMember.is_admin.desc(), GroupMember.joined_at.asc()).all()
    
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        
        target_member = GroupMember.query.filter_by(
            user_id=user_id,
            group_id=group_id
        ).first()
        
        target_user = User.query.get(user_id)
        
        if action == 'add_admin':
            target_member.is_admin = True
            create_notification(
                user_id=target_user.id,
                message=f'Você foi promovido a administrador no grupo {group.name}',
                link=url_for('group_chat', group_id=group_id)
            )
        elif action == 'remove_admin':
            target_member.is_admin = False
            create_notification(
                user_id=target_user.id,
                message=f'Você não é mais administrador no grupo {group.name}',
                link=url_for('group_chat', group_id=group_id)
            )
        elif action == 'mute':
            target_member.is_muted = True
            create_notification(
                user_id=target_user.id,
                message=f'Você foi mutado no grupo {group.name}',
                link=url_for('group_chat', group_id=group_id)
            )
        elif action == 'unmute':
            target_member.is_muted = False
            create_notification(
                user_id=target_user.id,
                message=f'Você foi desmutado no grupo {group.name}',
                link=url_for('group_chat', group_id=group_id)
            )
        elif action == 'remove':
            create_notification(
                user_id=target_user.id,
                message=f'Você foi removido do grupo {group.name}',
                link=url_for('dashboard'))
            db.session.delete(target_member)
        
        db.session.commit()
        flash('Ação realizada com sucesso!', 'success')
        return redirect(url_for('manage_group', group_id=group_id))
    
    return render_template('manage_group.html', group=group, members=members)

@app.route('/group/<int:group_id>/add_member', methods=['POST'])
@login_required
@admin_required
def add_member(group_id):
    group = Group.query.get_or_404(group_id)
    username = request.form.get('username')
    user_to_add = User.query.filter_by(username=username).first()
    
    if not user_to_add:
        flash('Usuário não encontrado', 'error')
    elif GroupMember.query.filter_by(user_id=user_to_add.id, group_id=group_id).first():
        flash('Este usuário já está no grupo', 'warning')
    else:
        new_member = GroupMember(user_id=user_to_add.id, group_id=group_id)
        db.session.add(new_member)
        
        create_notification(
            user_id=user_to_add.id,
            message=f'Você foi adicionado ao grupo {group.name}',
            link=url_for('group_chat', group_id=group_id)
        )
        
        db.session.commit()
        flash(f'{username} foi adicionado ao grupo!', 'success')
    
    return redirect(url_for('manage_group', group_id=group_id))

@app.route('/group/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()
    
    if not member:
        flash('Você não é membro deste grupo', 'error')
    else:
        db.session.delete(member)
        db.session.commit()
        flash('Você saiu do grupo com sucesso', 'success')
    
    return redirect(url_for('dashboard'))

# ========== MESSAGE ROUTES ==========
@app.route('/group/<int:group_id>/send', methods=['POST'])
@login_required
def send_group_message(group_id):
    member = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group_id
    ).first()
    
    if not member:
        flash('Você não é membro deste grupo', 'error')
        return redirect(url_for('dashboard'))
    
    if member.is_muted:
        flash('Você está mutado neste grupo e não pode enviar mensagens', 'error')
        return redirect(url_for('group_chat', group_id=group_id))
    
    if member.is_banned:
        flash('Você foi banido deste grupo', 'error')
        return redirect(url_for('dashboard'))
    
    content = request.form.get('content', '').strip()
    file = request.files.get('file')
    dice_roll = request.form.get('dice_roll')
    
    if not content and not file and not dice_roll:
        flash('Mensagem não pode estar vazia', 'error')
        return redirect(url_for('group_chat', group_id=group_id))
    
    message_type = 'text'
    file_path = None
    
    if dice_roll:
        content = f'🎲 Rolou {dice_roll}'
        message_type = 'dice'
    elif file and file.filename != '':
        if not allowed_file(file.filename):
            flash('Tipo de arquivo não permitido', 'error')
            return redirect(url_for('group_chat', group_id=group_id))
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Determine message type based on file extension
        ext = filename.rsplit('.', 1)[1].lower()
        if ext in {'png', 'jpg', 'jpeg', 'gif'}:
            message_type = 'image'
        else:
            message_type = 'file'
    
    new_message = Message(
        content=content,
        user_id=current_user.id,
        group_id=group_id,
        file_path=file_path,
        message_type=message_type
    )
    db.session.add(new_message)
    db.session.commit()
    
    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/message/<int:message_id>/edit', methods=['POST'])
@login_required
def edit_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    if message.user_id != current_user.id:
        flash('Você só pode editar suas próprias mensagens', 'error')
        return redirect(url_for('group_chat', group_id=message.group_id))
    
    new_content = request.form.get('content', '').strip()
    if not new_content:
        flash('Mensagem não pode estar vazia', 'error')
        return redirect(url_for('group_chat', group_id=message.group_id))
    
    message.content = new_content
    message.edited = True
    message.edited_at = datetime.utcnow()
    db.session.commit()
    
    flash('Mensagem editada com sucesso', 'success')
    return redirect(url_for('group_chat', group_id=message.group_id))
@app.route('/group/<int:group_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    if group.creator_id != current_user.id:
        flash('Apenas o criador do grupo pode deletá-lo', 'error')
        return redirect(url_for('manage_group', group_id=group_id))
    
    try:
        # Deletar mensagens e arquivos associados
        for message in group.messages:
            if message.file_path and os.path.exists(message.file_path):
                os.remove(message.file_path)
        
        for document in group.documents:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], document.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        db.session.delete(group)
        db.session.commit()
        
        flash('Grupo deletado com sucesso', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao deletar grupo: {str(e)}', 'error')
        return redirect(url_for('manage_group', group_id=group_id))
@app.route('/message/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    group_id = message.group_id
    
    # Check if user is message author or group admin
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()
    
    if not member or (message.user_id != current_user.id and not member.is_admin):
        flash('Você não tem permissão para deletar esta mensagem', 'error')
        return redirect(url_for('group_chat', group_id=group_id))
    
    # Delete associated file if exists
    if message.file_path and os.path.exists(message.file_path):
        os.remove(message.file_path)
    
    db.session.delete(message)
    db.session.commit()
    
    flash('Mensagem deletada com sucesso', 'success')
    return redirect(url_for('group_chat', group_id=group_id))

# ========== DOCUMENT ROUTES ==========
@app.route('/group/<int:group_id>/upload_document', methods=['POST'])
@login_required
def upload_group_document(group_id):
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()
    
    if not member:
        return jsonify({'success': False, 'error': 'Você não é membro deste grupo'}), 403
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Nenhum arquivo enviado'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Nome de arquivo vazio'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Tipo de arquivo não permitido'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # Get file size
    file_size = os.path.getsize(file_path)
    
    # Save document info to database
    ext = filename.rsplit('.', 1)[1].lower()
    new_document = GroupDocument(
        group_id=group_id,
        user_id=current_user.id,
        filename=filename,
        original_name=file.filename,
        file_type=ext,
        file_size=file_size
    )
    db.session.add(new_document)
    db.session.commit()
    
    return jsonify({'success': True})
@app.route('/delete_document/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    document = GroupDocument.query.get_or_404(document_id)
    
    # Verificar se o usuário tem permissão (admin ou dono do arquivo)
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=document.group_id
    ).first()
    
    if not member or (document.user_id != current_user.id and not member.is_admin):
        return jsonify({'success': False, 'error': 'Sem permissão'}), 403
    
    try:
        # Remover arquivo do sistema de arquivos
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remover do banco de dados
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/view_document/<filename>')
@login_required
def view_document(filename):
    # Verificar se o usuário tem permissão para ver o arquivo
    document = GroupDocument.query.filter_by(filename=filename).first_or_404()
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=document.group_id
    ).first()
    
    if not member:
        abort(403)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route('/uploads/<filename>')
@login_required
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ========== AUTH ROUTES ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Login inválido. Verifique seu nome de usuário e senha', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Basic validation
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já está em uso', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email já está em uso', 'error')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username,
                email=email,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash('Conta criada com sucesso! Faça login para continuar', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado com sucesso', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    # Get user's groups count
    groups_count = GroupMember.query.filter_by(user_id=current_user.id).count()
    
    # Get user's messages count
    messages_count = Message.query.filter_by(user_id=current_user.id).count()
    
    return render_template('profile.html', 
                         user=current_user,
                         groups_count=groups_count,
                         messages_count=messages_count)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form.get('bio', '')
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f'user_{current_user.id}_profile.{file.filename.rsplit(".", 1)[1].lower()}')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Delete old profile picture if exists
                if current_user.profile_picture and os.path.exists(current_user.profile_picture):
                    os.remove(current_user.profile_picture)
                
                current_user.profile_picture = file_path
        
        db.session.commit()
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=current_user)

# ========== API ROUTES ==========
@app.route('/api/notifications/count')
@login_required
def get_unread_notifications_count():
    count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()
    
    return jsonify({'count': count})

@app.route('/api/messages/<int:group_id>')
@login_required
def get_messages(group_id):
    # Verify user is member of the group
    member = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()
    
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    last_message_id = request.args.get('last_message_id', 0, type=int)
    
    messages = Message.query.filter(
        Message.group_id == group_id,
        Message.id > last_message_id
    ).order_by(Message.timestamp.asc()).all()
    
    messages_data = [{
        'id': msg.id,
        'content': msg.content,
        'user_id': msg.user_id,
        'username': msg.author.username,
        'timestamp': msg.timestamp.isoformat(),
        'message_type': msg.message_type,
        'file_path': url_for('uploaded_file', filename=os.path.basename(msg.file_path)) if msg.file_path else None
    } for msg in messages]
    
    return jsonify(messages_data)

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Initialize database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
