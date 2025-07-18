# ==============================================================================
# 1. IMPORTAÇÕES
# ==============================================================================
import os
import uuid
import fitz  # PyMuPDF
from datetime import date, datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func

# Importações dos modelos do banco de dados
from models import db, User, Document, Department, UserRole, Bulletin, ApprovalStatus

# ==============================================================================
# 2. CONFIGURAÇÃO DA APLICAÇÃO FLASK
# ==============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-segura-e-dificil-de-adivinhar'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ged_user:Ged20078@localhost/ged_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Limite de 10MB

# Inicializa o banco de dados e o gerenciador de login com a aplicação
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça o login para acessar esta página."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==============================================================================
# 3. FUNÇÕES AUXILIARES E DECORATORS
# ==============================================================================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

def extract_text_from_pdf(filepath):
    try:
        with fitz.open(filepath) as doc:
            text = ""
            for page in doc:
                text += page.get_text()
            return text
    except Exception as e:
        print(f"Erro ao extrair texto do PDF: {e}")
        return ""

def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            allowed_roles_names = [r.name for r in roles]
            if current_user.role.name not in allowed_roles_names:
                flash('Acesso negado. Você não tem permissão para acessar esta página.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# ==============================================================================
# 4. ROTAS DE AUTENTICAÇÃO E MINHA CONTA
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username_from_form = request.form.get('username')
        user = User.query.filter(func.lower(User.username) == func.lower(username_from_form)).first()
        
        if user and user.check_password(request.form.get('password')):
            if not user.is_active:
                flash('Sua conta está desativada. Por favor, contate um administrador.', 'warning')
                return redirect(url_for('login'))
            
            if user.approval_status != ApprovalStatus.APPROVED:
                flash('Sua conta ainda não foi aprovada por um administrador.', 'info')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Usuário ou senha inválidos.', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    if request.method == 'POST':
        return "Logged out", 200 
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        department_ids = request.form.getlist('department_ids')
        if not department_ids:
            flash('Você deve selecionar pelo menos um departamento.', 'danger')
            departments = Department.query.order_by(Department.name).all()
            return render_template('register.html', departments=departments)

        new_user = User(
            username=request.form['username'],
            role=UserRole.VIEWER,
            approval_status=ApprovalStatus.PENDING
        )
        new_user.set_password(request.form['password'])
        
        for dept_id in department_ids:
            dept = Department.query.get(dept_id)
            if dept:
                new_user.departments.append(dept)

        db.session.add(new_user)
        db.session.commit()
        
        flash('Registo enviado! A sua conta será ativada após aprovação de um administrador.', 'success')
        return redirect(url_for('login'))
        
    departments = Department.query.order_by(Department.name).all()
    return render_template('register.html', departments=departments)

@app.route('/my_account', methods=['GET', 'POST'])
@login_required
def my_account():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_user.check_password(current_password):
            flash('Sua senha atual está incorreta.', 'danger')
            return redirect(url_for('my_account'))
        
        if len(new_password) < 4:
            flash('A nova senha deve ter pelo menos 4 caracteres.', 'danger')
            return redirect(url_for('my_account'))

        if new_password != confirm_password:
            flash('A nova senha e a confirmação não correspondem.', 'danger')
            return redirect(url_for('my_account'))

        current_user.set_password(new_password)
        db.session.commit()
        flash('Sua senha foi alterada com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('my_account.html')

# ==============================================================================
# 5. ROTAS PRINCIPAIS E DE DOCUMENTOS
# ==============================================================================
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    query = Document.query.filter_by(is_active=True)
    
    selected_dept_id = request.args.get('department_id', type=int)
    doc_type_filter = request.args.get('doc_type_filter', type=str)
    search_query = request.args.get('q', '')

    geral_dept = Department.query.filter_by(name='Geral').first()
    geral_dept_id = geral_dept.id if geral_dept else -1

    if current_user.role == UserRole.ADMIN:
        if selected_dept_id:
            query = query.filter_by(department_id=selected_dept_id)
    else:
        user_dept_ids = [dept.id for dept in current_user.departments]
        query = query.filter(db.or_(
            Document.department_id.in_(user_dept_ids),
            Document.department_id == geral_dept_id
        ))

    if doc_type_filter:
        query = query.filter_by(doc_type=doc_type_filter)
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(db.or_(
            Document.title.ilike(search_term),
            Document.content.ilike(search_term)
        ))

    documents = query.order_by(Document.upload_date.desc()).all()
    
    doc_types = [item[0] for item in db.session.query(Document.doc_type).filter_by(is_active=True).distinct().order_by(Document.doc_type).all()]
    all_departments = []
    if current_user.role == UserRole.ADMIN:
        all_departments = Department.query.order_by(Department.name).all()

    return render_template('dashboard.html', 
                           documents=documents, 
                           departments=all_departments, 
                           doc_types=doc_types,
                           selected_dept_id=selected_dept_id,
                           selected_doc_type=doc_type_filter,
                           search_query=search_query)

@app.route('/upload_document', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def upload_document():
    if request.method == 'POST':
        form_data = request.form
        file = request.files.get('file')
        doc_type = form_data.get('doc_type', '').upper()
        doc_number_str = form_data.get('doc_number')
        doc_revision_str = form_data.get('doc_revision')
        revision_date_str = form_data.get('revision_date')
        department_id = form_data.get('department_id')

        if not all([file, file.filename, doc_type, doc_number_str, doc_revision_str, revision_date_str, department_id]) or not allowed_file(file.filename):
            flash('Todos os campos e um arquivo PDF válido são obrigatórios.', 'danger')
            return redirect(request.url)
        
        doc_number = int(doc_number_str)
        doc_revision = int(doc_revision_str)
        revision_date = datetime.strptime(revision_date_str, '%Y-%m-%d').date()

        existing_doc = Document.query.filter_by(
            doc_type=doc_type, 
            doc_number=doc_number,
            department_id=department_id,
            is_active=True
        ).first()

        previous_version_id = None
        if existing_doc:
            if doc_revision <= existing_doc.doc_revision:
                flash(f'Erro: A nova revisão ({doc_revision}) deve ser maior que a revisão atual ({existing_doc.doc_revision}) para este documento neste departamento.', 'danger')
                return redirect(request.url)
            
            existing_doc.is_active = False
            previous_version_id = existing_doc.id
            db.session.add(existing_doc)

        original_filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}.pdf"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        try:
            doc_pdf = fitz.open(filepath)
            content = ""
            for page in doc_pdf:
                content += page.get_text()
            permissions = int(fitz.PDF_PERM_PRINT | fitz.PDF_PERM_COPY)
            temp_filepath = filepath + ".tmp"
            doc_pdf.save(temp_filepath, incremental=False, encryption=fitz.PDF_ENCRYPT_NONE, permissions=permissions)
            doc_pdf.close()
            os.remove(filepath)
            os.rename(temp_filepath, filepath)
        except Exception as e:
            print(f"Erro ao processar PDF: {e}")
            flash('Ocorreu um erro ao processar o PDF.', 'danger')
            return redirect(request.url)

        new_doc = Document(
            original_filename=original_filename,
            stored_filename=unique_filename,
            title=form_data.get('title', original_filename),
            content=content,
            uploader_id=current_user.id,
            department_id=department_id,
            doc_type=doc_type,
            doc_number=doc_number,
            doc_revision=doc_revision,
            revision_date=revision_date,
            previous_version_id=previous_version_id
        )
        db.session.add(new_doc)
        db.session.commit()
        
        flash('Documento enviado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    
    departments = Department.query.order_by(Department.name).all()
    return render_template('upload_document.html', departments=departments)

@app.route('/view/<int:doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    geral_dept = Department.query.filter_by(name='Geral').first()
    geral_dept_id = geral_dept.id if geral_dept else -1
    user_dept_ids = [dept.id for dept in current_user.departments]

    if not (doc.department_id in user_dept_ids or 
            doc.department_id == geral_dept_id or 
            current_user.role == UserRole.ADMIN):
        flash('Acesso negado. Você não tem permissão para ver este documento.', 'danger')
        return redirect(url_for('dashboard'))

    history = []
    current_version = doc
    while current_version.previous_version:
        history.append(current_version.previous_version)
        current_version = current_version.previous_version

    return render_template('viewer.html', 
                           filename=doc.stored_filename, 
                           doc_title=doc.title,
                           document=doc,
                           history=history)

@app.route('/uploads/<filename>')
@login_required
def serve_file(filename):
    doc = Document.query.filter_by(stored_filename=filename).first_or_404()
    geral_dept = Department.query.filter_by(name='Geral').first()
    geral_dept_id = geral_dept.id if geral_dept else -1
    user_dept_ids = [dept.id for dept in current_user.departments]

    if (doc.department_id in user_dept_ids or 
        doc.department_id == geral_dept_id or 
        current_user.role == UserRole.ADMIN):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    return "Acesso negado", 403

# ==============================================================================
# 6. ROTAS DE GERENCIAMENTO (ADMINS E UPLOADERS)
# ==============================================================================
@app.route('/manage_documents')
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def manage_documents():
    query = Document.query
    
    selected_dept_id = request.args.get('department_id', type=int)
    doc_type_filter = request.args.get('doc_type_filter', type=str)
    search_query = request.args.get('q', '')

    if current_user.role == UserRole.ADMIN:
        if selected_dept_id:
            query = query.filter_by(department_id=selected_dept_id)
    else: 
        user_dept_ids = [dept.id for dept in current_user.departments]
        query = query.filter(Document.department_id.in_(user_dept_ids))
    
    if doc_type_filter:
        query = query.filter_by(doc_type=doc_type_filter)
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(db.or_(
            Document.title.ilike(search_term),
            Document.content.ilike(search_term)
        ))

    documents = query.order_by(Document.upload_date.desc()).all()
    
    doc_types = [item[0] for item in db.session.query(Document.doc_type).distinct().order_by(Document.doc_type).all()]
    all_departments = []
    if current_user.role == UserRole.ADMIN:
        all_departments = Department.query.order_by(Department.name).all()

    return render_template('manage_documents.html', 
                           documents=documents, 
                           departments=all_departments, 
                           doc_types=doc_types,
                           selected_dept_id=selected_dept_id,
                           selected_doc_type=doc_type_filter,
                           search_query=search_query)

@app.route('/documents/toggle_status/<int:doc_id>', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def toggle_document_status(doc_id):
    doc_to_toggle = Document.query.get_or_404(doc_id)
    doc_to_toggle.is_active = not doc_to_toggle.is_active
    db.session.commit()
    status = "reativado" if doc_to_toggle.is_active else "arquivado como obsoleto"
    flash(f'O documento "{doc_to_toggle.title}" foi {status}.', 'info')
    return redirect(request.referrer or url_for('manage_documents'))

@app.route('/document_history/<int:doc_id>')
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def document_history(doc_id):
    start_doc = Document.query.get_or_404(doc_id)
    head_revision = start_doc
    while head_revision.next_versions:
        head_revision = head_revision.next_versions[0]
    history = []
    current_version = head_revision
    while current_version:
        history.append(current_version)
        current_version = current_version.previous_version
        
    return render_template('document_history.html', 
                           history=history, 
                           doc_code=f"{head_revision.doc_type}-{head_revision.doc_number:02d}",
                           department_name=head_revision.department.name)

@app.route('/departments', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def departments():
    if request.method == 'POST':
        name = request.form.get('name')
        if name and not Department.query.filter_by(name=name).first():
            new_dept = Department(name=name)
            db.session.add(new_dept)
            db.session.commit()
            flash(f'Departamento "{name}" criado com sucesso.', 'success')
        else:
            flash('Nome de departamento inválido ou já existe.', 'danger')
        return redirect(url_for('departments'))
    all_departments = Department.query.order_by(Department.name).all()
    return render_template('departments.html', departments=all_departments)

@app.route('/departments/edit/<int:dept_id>', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def edit_department(dept_id):
    dept_to_edit = Department.query.get_or_404(dept_id)
    if request.method == 'POST':
        new_name = request.form.get('name')
        existing_dept = Department.query.filter(Department.name == new_name, Department.id != dept_id).first()
        if new_name and not existing_dept:
            dept_to_edit.name = new_name
            db.session.commit()
            flash('Nome do departamento atualizado com sucesso!', 'success')
            return redirect(url_for('departments'))
        else:
            flash('Nome inválido ou já em uso por outro departamento.', 'danger')
    return render_template('edit_department.html', department=dept_to_edit)

@app.route('/users', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def users():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        department_ids = request.form.getlist('department_ids')
        role_name = request.form.get('role')

        if not all([username, password, department_ids, role_name]):
            flash('Todos os campos são obrigatórios.', 'danger')
            return redirect(url_for('users'))
        
        if User.query.filter_by(username=username).first():
            flash('Este nome de usuário já existe.', 'danger')
            return redirect(url_for('users'))

        new_user = User(
            username=username,
            role=UserRole[role_name]
        )
        new_user.set_password(password)

        for dept_id in department_ids:
            dept = Department.query.get(dept_id)
            if dept:
                new_user.departments.append(dept)

        db.session.add(new_user)
        db.session.commit()
        flash(f'Usuário "{username}" criado com sucesso.', 'success')
        return redirect(url_for('users'))
    
    all_users = User.query.order_by(User.username).all()
    all_departments = Department.query.order_by(Department.name).all()
    return render_template('users.html', users=all_users, departments=all_departments, roles=UserRole)

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    if request.method == 'POST':
        new_department_ids = request.form.getlist('department_ids')
        new_role_name = request.form.get('role')

        if user_to_edit.id == current_user.id and new_role_name != 'ADMIN':
            flash('Você não pode remover seu próprio status de Administrador.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

        user_to_edit.role = UserRole[new_role_name]
        
        user_to_edit.departments.clear()
        for dept_id in new_department_ids:
            dept = Department.query.get(dept_id)
            if dept:
                user_to_edit.departments.append(dept)
        
        db.session.commit()
        flash(f'Dados do usuário "{user_to_edit.username}" atualizados com sucesso!', 'success')
        return redirect(url_for('users'))
        
    all_departments = Department.query.order_by(Department.name).all()
    return render_template('edit_user.html', 
                           user=user_to_edit, 
                           departments=all_departments, 
                           roles=UserRole)

@app.route('/users/change_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN)
def change_password(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    if request.method == 'POST':
        new_password = request.form.get('password')
        if not new_password or len(new_password) < 4:
            flash('A nova senha deve ter pelo menos 4 caracteres.', 'danger')
        else:
            user_to_edit.set_password(new_password)
            db.session.commit()
            flash(f'Senha do usuário "{user_to_edit.username}" alterada com sucesso!', 'success')
            return redirect(url_for('users'))
    return render_template('change_password.html', user=user_to_edit)

@app.route('/users/toggle_status/<int:user_id>', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN)
def toggle_status(user_id):
    if user_id == current_user.id:
        flash('Você não pode desativar sua própria conta.', 'danger')
        return redirect(url_for('users'))
    user_to_toggle = User.query.get_or_404(user_id)
    user_to_toggle.is_active = not user_to_toggle.is_active
    db.session.commit()
    status = "ativado" if user_to_toggle.is_active else "desativado"
    flash(f'Usuário "{user_to_toggle.username}" foi {status}.', 'info')
    return redirect(url_for('users'))

@app.route('/users/approve/<int:user_id>', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN)
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.approval_status = ApprovalStatus.APPROVED
    db.session.commit()
    flash(f'Utilizador "{user.username}" aprovado com sucesso.', 'success')
    return redirect(url_for('users'))

@app.route('/users/reject/<int:user_id>', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN)
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    user.approval_status = ApprovalStatus.REJECTED
    db.session.commit()
    flash(f'Utilizador "{user.username}" rejeitado.', 'warning')
    return redirect(url_for('users'))

# ==============================================================================
# 7. ROTAS DO BOLETIM INFORMATIVO
# ==============================================================================
@app.route('/bulletins')
@login_required
def bulletins():
    all_bulletins = Bulletin.query.filter(
        Bulletin.expiration_date >= date.today()
    ).order_by(Bulletin.creation_date.desc()).all()
    return render_template('bulletins.html', bulletins=all_bulletins)

@app.route('/manage_bulletins', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def manage_bulletins():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        expiration_str = request.form.get('expiration_date')
        if not all([title, content, expiration_str]):
            flash('Todos os campos são obrigatórios.', 'danger')
        else:
            expiration_date = datetime.strptime(expiration_str, '%Y-%m-%d').date()
            new_bulletin = Bulletin(
                title=title,
                content=content,
                expiration_date=expiration_date,
                author_id=current_user.id
            )
            db.session.add(new_bulletin)
            db.session.commit()
            flash('Boletim informativo criado com sucesso!', 'success')
        return redirect(url_for('manage_bulletins'))
    
    all_bulletins = Bulletin.query.order_by(Bulletin.creation_date.desc()).all()
    return render_template('manage_bulletins.html', bulletins=all_bulletins, today=date.today())

@app.route('/bulletins/edit/<int:bulletin_id>', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def edit_bulletin(bulletin_id):
    bulletin_to_edit = Bulletin.query.get_or_404(bulletin_id)
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        expiration_str = request.form.get('expiration_date')

        if not all([title, content, expiration_str]):
            flash('Todos os campos são obrigatórios.', 'danger')
        else:
            bulletin_to_edit.title = title
            bulletin_to_edit.content = content
            bulletin_to_edit.expiration_date = datetime.strptime(expiration_str, '%Y-%m-%d').date()
            
            db.session.commit()
            flash('Boletim atualizado com sucesso!', 'success')
            return redirect(url_for('manage_bulletins'))

    return render_template('edit_bulletin.html', bulletin=bulletin_to_edit)

@app.route('/bulletins/delete/<int:bulletin_id>', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.UPLOADER)
def delete_bulletin(bulletin_id):
    bulletin_to_delete = Bulletin.query.get_or_404(bulletin_id)
    db.session.delete(bulletin_to_delete)
    db.session.commit()
    flash('Boletim apagado com sucesso.', 'info')
    return redirect(url_for('manage_bulletins'))

# ==============================================================================
# 8. INICIALIZAÇÃO DA APLICAÇÃO
# ==============================================================================
if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        db.create_all()
        
        if not Department.query.filter_by(name='Geral').first():
            print("Criando departamento 'Geral'...")
            geral_dept = Department(name='Geral')
            db.session.add(geral_dept)
            db.session.commit()

        if User.query.count() == 0:
            print("Nenhum usuário encontrado. Criando usuário 'admin'.")
            admin_dept = Department.query.filter_by(name='Geral').first()
            admin_user = User(username='admin', role=UserRole.ADMIN, approval_status=ApprovalStatus.APPROVED)
            admin_user.departments.append(admin_dept)
            admin_user.set_password('admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Usuário 'admin' com senha 'admin' criado.")

    app.run()
