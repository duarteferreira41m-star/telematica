from flask import Flask, render_template, redirect, url_for, request, abort, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from io import BytesIO
# CORREÇÃO: Certifique-se de que o nome do módulo de importação corresponde ao seu arquivo de configuração.
# Se o seu arquivo de configuração se chama 'config_new.py', a importação deve ser 'from config_new import Config'.
from config_new import Config


# Inicialização do Flask e configuração
app = Flask(__name__)
app.config.from_object(Config)

# Inicializando o banco de dados
db = SQLAlchemy(app)

# Inicializando o LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Carregar os modelos - A instância 'db' deve ser inicializada antes de importar os modelos.
# O 'models.py' deve importar 'db' de 'app.py' (e não inicializá-lo novamente).
from models import User, Viatura

# Função de carregamento do usuário para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """
    Carrega um usuário pelo ID para o Flask-Login.
    """
    return User.query.get(int(user_id))

# 1. Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Rota para o login de usuários.
    Processa as credenciais e autentica o usuário.
    """
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        user = User.query.filter_by(nome=nome).first()
        if user and user.check_password(senha):
            login_user(user, remember='remember' in request.form)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nome de usuário ou senha incorretos', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

# 2. Página Inicial (Dashboard)
@app.route('/index')
@login_required
def index():
    """
    Página inicial da aplicação, acessível apenas por usuários logados.
    """
    return render_template('index.html')

# 3. Rota de Unidades (com base no tipo de usuário)
@app.route('/unidade', methods=['GET', 'POST'])
@login_required
def unidade():
    """
    Exibe as unidades disponíveis.
    Usuários 'local' veem apenas sua unidade; outros veem todas as unidades.
    """
    if current_user.tipo == 'local':
        unidades = [current_user.unidade]
    else:
        unidades = ['E.M', '1ªCIA', '2ªCIA', '3ªCIA', '4ªCIA', '5ªCIA', '6ªCIA', 'CIA FT']
    return render_template('unidade.html', unidades=unidades)

# 4. Rota para detalhes de uma unidade
# A importação de 'datetime' e 'flash' é redundante aqui se já estiver no topo do arquivo.
from datetime import datetime
from flask import render_template, flash # Estas importações são redundantes se já no topo

@app.route('/unidade/<unidade>', methods=['GET', 'POST'])
@login_required
def unidade_detalhes(unidade):
    """
    Exibe a lista de viaturas para uma unidade específica.
    Formata a data de baixa para exibição.
    """
    try:
        # Buscando todas as viaturas da unidade especificada
        viaturas = Viatura.query.filter_by(unidade=unidade).all()

        # Verificando se há viaturas para a unidade
        if not viaturas:
            flash(f'Nenhuma viatura encontrada para a unidade {unidade}.', 'warning')

        # Formatação da data de baixa
        for viatura in viaturas:
            if viatura.data_baixa:
                # Formata a data de baixa para o formato 'dd/mm/yyyy'
                viatura.data_baixa_formatada = viatura.data_baixa.strftime('%d/%m/%Y')
            else:
                # Se não houver data de baixa, atribui 'N/A'
                viatura.data_baixa_formatada = 'N/A'

        # Retornando o template com as viaturas e unidade
        return render_template('unidade_detalhes.html', unidade=unidade, viaturas=viaturas)

    except Exception as e:
        flash(f'Ocorreu um erro ao buscar as viaturas para a unidade {unidade}: {e}', 'danger')
        return render_template('unidade_detalhes.html', unidade=unidade, viaturas=[])

# 5. Inserir Viatura em uma Unidade
@app.route('/unidade/<unidade>/inserir', methods=['GET', 'POST'])
@login_required
def unidade_inserir(unidade):
    """
    Rota para inserir uma nova viatura em uma unidade.
    Usuários 'local' só podem inserir em sua própria unidade.
    """
    if current_user.tipo == 'local' and current_user.unidade != unidade:
        abort(403)  # Usuário local não pode acessar outra unidade

    if request.method == 'POST':
        prefixo = request.form['prefixo']
        placa = request.form['placa']
        status = request.form['status']
        motivo_baixa = local_baixa = data_baixa = None

        if status == 'baixada':
            motivo_baixa = request.form['motivo_baixa']
            local_baixa = request.form['local_baixa']
            # Converte a string da data para um objeto datetime
            try:
                data_baixa = datetime.strptime(request.form['data_baixa'], '%Y-%m-%d')
            except ValueError:
                flash('Formato de data inválido. Use AAAA-MM-DD.', 'danger')
                return redirect(url_for('unidade_inserir', unidade=unidade))

        nova_viatura = Viatura(prefixo=prefixo, placa=placa, status=status, unidade=unidade,
                               motivo_baixa=motivo_baixa, local_baixa=local_baixa, data_baixa=data_baixa)

        db.session.add(nova_viatura)
        db.session.commit()

        flash('Viatura adicionada com sucesso!', 'success')
        return redirect(url_for('unidade_detalhes', unidade=unidade))

    return render_template('inserir_viatura.html', unidade=unidade)

# 6. Consulta Geral das Viaturas
@app.route('/unidade/<unidade>/consulta_geral', methods=['GET', 'POST'])
@login_required
def consulta_geral(unidade):
    """
    Exibe uma consulta geral das viaturas de uma unidade, com filtro por status.
    """
    # Filtrando viaturas por unidade
    viaturas = Viatura.query.filter_by(unidade=unidade).all()

    # Filtro por status
    if request.method == 'POST':
        status_filtro = request.form.get('status')
        if status_filtro and status_filtro != 'todos': # Adicionado 'todos' para ver todas as viaturas
            viaturas = [v for v in viaturas if v.status == status_filtro]

    # Formatação de data para cada viatura
    for viatura in viaturas:
        if viatura.data_baixa:
            viatura.data_baixa_formatada = viatura.data_baixa.strftime('%d/%m/%Y')
        else:
            viatura.data_baixa_formatada = 'N/A'

    return render_template('consulta_geral.html', unidade=unidade, viaturas=viaturas)

# 7. Consulta Individual das Viaturas
@app.route('/unidade/<unidade>/consulta_individual', methods=['GET', 'POST'])
@login_required
def consulta_individual(unidade):
    """
    Permite a consulta individual de viaturas por prefixo, placa ou patrimônio.
    """
    viaturas = []

    if request.method == 'POST':
        campo = request.form.get('campo')
        valor = request.form.get('valor')

        # Consultar por prefixo, placa ou patrimônio
        if campo == 'prefixo':
            viaturas = Viatura.query.filter_by(prefixo=valor, unidade=unidade).all() # Adicionado filtro por unidade
        elif campo == 'placa':
            viaturas = Viatura.query.filter_by(placa=valor, unidade=unidade).all() # Adicionado filtro por unidade
        elif campo == 'patrimonio':
            viaturas = Viatura.query.filter_by(id=valor, unidade=unidade).all() # Adicionado filtro por unidade

    # Formatação de data
    for viatura in viaturas:
        if viatura.data_baixa:
            viatura.data_baixa_formatada = viatura.data_baixa.strftime('%d/%m/%Y')
        else:
            viatura.data_baixa_formatada = 'N/A'

    return render_template('consulta_individual.html', unidade=unidade, viaturas=viaturas)

# 8. Gerar Relatório de Viaturas em Excel
@app.route('/relatorio', methods=['GET', 'POST'])
@login_required
def relatorio():
    """
    Gera um relatório das viaturas em formato Excel, com opção de filtro por status.
    Usuários 'local' veem apenas suas viaturas.
    """
    if current_user.tipo == 'local':
        viaturas = Viatura.query.filter_by(unidade=current_user.unidade).all()
    else:
        viaturas = Viatura.query.all()

    if request.method == 'POST':
        status_filtro = request.form.get('status')
        if status_filtro and status_filtro != 'todos':
            viaturas = [v for v in viaturas if v.status == status_filtro]

    # Cria um DataFrame Pandas com os dados das viaturas
    df = pd.DataFrame([(v.prefixo, v.placa, v.status, v.data_baixa_formatada if hasattr(v, 'data_baixa_formatada') else 'N/A', v.unidade) for v in viaturas],
                      columns=['Prefixo', 'Placa', 'Status', 'Data Baixa', 'Unidade'])

    # Gera o arquivo Excel em memória
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Viaturas')
    output.seek(0)

    return send_file(output, as_attachment=True, download_name='relatorio_viaturas.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# 9. Função para verificar se o usuário é administrador (decorador)
def admin_required(f):
    """
    Decorador para restringir o acesso a rotas apenas para usuários administradores.
    """
    # Importação para usar 'wraps' e manter metadados da função original
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.tipo != 'admin':
            abort(403)  # Proibido acessar
        return f(*args, **kwargs)
    return wrapper

# 10. Criar Novo Usuário (Somente Administrador)
@app.route('/criar_usuario', methods=['GET', 'POST'])
@login_required
@admin_required
def criar_usuario():
    """
    Rota para criar um novo usuário. Apenas administradores podem acessar.
    """
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        tipo = request.form['tipo']
        unidade = request.form.get('unidade') if tipo == 'local' else None # Pega unidade se for local

        # Verifica se o usuário já existe
        if User.query.filter_by(nome=nome).first():
            flash('Nome de usuário já existe. Escolha outro.', 'danger')
            return redirect(url_for('criar_usuario'))

        novo_usuario = User(nome=nome, tipo=tipo, unidade=unidade)
        novo_usuario.set_password(senha)

        db.session.add(novo_usuario)
        db.session.commit()

        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('admin')) # Redireciona para a página de administração de usuários

    # Para 'criar_usuario.html', pode ser útil passar as unidades disponíveis
    unidades_disponiveis = ['E.M', '1ªCIA', '2ªCIA', '3ªCIA', '4ªCIA', '5ªCIA', '6ªCIA', 'CIA FT']
    return render_template('criar_usuario.html', unidades=unidades_disponiveis)

# 11. Excluir Usuário (Somente Administrador)
@app.route('/excluir_usuario/<int:id>', methods=['POST']) # ALTERADO para POST por segurança
@login_required
@admin_required
def excluir_usuario(id):
    """
    Rota para excluir um usuário. Apenas administradores podem acessar.
    Alterado para método POST para maior segurança.
    """
    usuario = User.query.get_or_404(id) # Use get_or_404 para melhor tratamento de erros
    db.session.delete(usuario)
    db.session.commit()

    flash(f'Usuário {usuario.nome} excluído com sucesso!', 'success')
    return redirect(url_for('admin'))

# 12. Admin - Página de Administração de Usuários
@app.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin():
    """
    Página de administração de usuários. Apenas administradores podem acessar.
    Lista todos os usuários.
    """
    usuarios = User.query.all()
    return render_template('admin.html', usuarios=usuarios)

# 13. Editar Usuário (Somente Administrador)
@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(id):
    """
    Rota para editar um usuário existente. Apenas administradores podem acessar.
    """
    usuario = User.query.get_or_404(id) # Use get_or_404 para melhor tratamento de erros
    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.tipo = request.form['tipo']
        usuario.unidade = request.form.get('unidade') if usuario.tipo == 'local' else None # Atualiza unidade

        if request.form['senha']:
            usuario.set_password(request.form['senha'])

        db.session.commit()

        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin'))

    unidades_disponiveis = ['E.M', '1ªCIA', '2ªCIA', '3ªCIA', '4ªCIA', '5ªCIA', '6ªCIA', 'CIA FT']
    return render_template('editar_usuario.html', usuario=usuario, unidades=unidades_disponiveis)

# 14. Função para lidar com erro 403 (Acesso Proibido)
@app.errorhandler(403)
def forbidden_error(error):
    """
    Tratador de erro personalizado para acesso proibido (403).
    """
    return render_template('403.html'), 403

# 15. Rota de Logout
@app.route('/logout')
@login_required
def logout():
    """
    Rota para realizar o logout do usuário.
    """
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

# Rota padrão para a raiz do site, redireciona para o login
@app.route('/')
def root():
    return redirect(url_for('login'))

# Rodar a aplicação
if __name__ == '__main__':
    # Em produção, você não deve usar debug=True.
    # Use um servidor WSGI como Gunicorn ou uWSGI.
    app.run(debug=True)
