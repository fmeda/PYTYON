import os
import logging
from flask import Flask, request, jsonify, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
import bcrypt
import ldap3
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuração do Flask
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'supersecretkey')  # Secret key de ambiente
jwt = JWTManager(app)

# Configuração do MongoDB
client = MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
db = client['odin_security']
users_collection = db['users']
firewall_rules_collection = db['firewall_rules']

# Simulação de integração com AD/LDAP
def authenticate_ldap(username, password):
    try:
        server = ldap3.Server(os.getenv('LDAP_SERVER', 'ldap://ad.example.com'))
        conn = ldap3.Connection(server, user=f'cn={username},dc=example,dc=com', password=password, auto_bind=True)
        return conn.bound
    except ldap3.LDAPException as e:
        logger.error(f'Erro de autenticação LDAP: {e}')
        return False

# Registro de usuário com hash seguro
def register_user(username, password):
    if users_collection.find_one({'username': username}):
        raise ValueError('Usuário já existe.')
    
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users_collection.insert_one({'username': username, 'password': hashed_password})
    logger.info(f'Usuário {username} registrado com sucesso')

# Autenticação com JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        abort(400, description="Usuário e senha são obrigatórios.")

    user = users_collection.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode(), user['password']):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    
    return jsonify({'message': 'Credenciais inválidas'}), 401

# Adicionar regra de firewall de forma automatizada
@app.route('/firewall/rule', methods=['POST'])
@jwt_required()
def add_firewall_rule():
    current_user = get_jwt_identity()
    data = request.json
    required_fields = ['source', 'destination', 'port', 'action']
    
    if not all(field in data for field in required_fields):
        abort(400, description="Campos obrigatórios: 'source', 'destination', 'port', 'action'.")

    rule = {
        'source': data.get('source'),
        'destination': data.get('destination'),
        'port': data.get('port'),
        'action': data.get('action'),
        'created_by': current_user
    }

    firewall_rules_collection.insert_one(rule)
    logger.info(f'Regra adicionada: {rule}')
    return jsonify({'message': 'Regra adicionada com sucesso'}), 201

# Listar regras do firewall
@app.route('/firewall/rules', methods=['GET'])
@jwt_required()
def list_firewall_rules():
    rules = list(firewall_rules_collection.find({}, {'_id': 0}))
    return jsonify(rules), 200

# Rota para visualizar detalhes de um usuário (exemplo de feature adicional)
@app.route('/user/<username>', methods=['GET'])
@jwt_required()
def get_user(username):
    user = users_collection.find_one({'username': username}, {'_id': 0})
    if user:
        return jsonify(user), 200
    return jsonify({'message': 'Usuário não encontrado'}), 404

# Tratamento global de erros
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': str(error)}), 400

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erro interno: {error}")
    return jsonify({'error': 'Erro interno no servidor'}), 500

if __name__ == '__main__':
    app.run(debug=True)
