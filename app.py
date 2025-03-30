from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/auth_system'
app.config['SECRET_KEY'] = '333'
mongo = PyMongo(app)

# Rota para servir o arquivo HTML
@app.route('/')
def serve_html():
    return send_from_directory(os.path.dirname(__file__), 'app.html')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token ausente!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = mongo.db.users.find_one({'_id': data['id']})
        except:
            return jsonify({'message': 'Token inválido!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    user = {
        'username': data['username'],
        'password': hashed_password,
        'isAdmin': data.get('isAdmin', False)
    }
    mongo.db.users.insert_one(user)
    return jsonify({'message': 'Usuário registrado com sucesso!'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = mongo.db.users.find_one({'username': data['username']})
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Credenciais inválidas!'}), 401
    
    token = jwt.encode({'id': str(user['_id']), 'isAdmin': user['isAdmin'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token, 'isAdmin': user['isAdmin']})

if __name__ == '__main__':
    app.run(debug=True, port=5000)

#Adicionar Escolinhas de futebol 
@app.route('/add_school', methods=['POST'])
@token_required
def add_school(current_user):
    if not current_user['isAdmin']:
        return jsonify({'message': 'Apenas administradores podem adicionar escolinhas!'}), 403
    
    data = request.get_json()
    school = {
        'name': data['name'],
        'location': data['location'],
        'contact': data['contact']
    }
    mongo.db.schools.insert_one(school)
    return jsonify({'message': 'Escolinha adicionada com sucesso!'})


#Listar escolinhas de futebol adicionadas 
@app.route('/schools', methods=['GET'])
def get_schools():
    schools = list(mongo.db.schools.find({}, {'_id': 0}))
    return jsonify(schools)

if __name__ == '__main__':
    app.run(debug=True, port=5000)