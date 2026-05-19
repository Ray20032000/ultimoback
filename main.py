import os
import fdb
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

CORS(app, supports_credentials=True,
     origins=[
         "http://localhost:5173",
         "http://127.0.0.1:5173",
         "http://10.92.3.139:5173"
     ])

app.config['SECRET_KEY'] = 'chave_secreta_projeto_vendas'

UPLOAD_FOLDER = os.path.join('uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def get_db_connection():
    try:

        print("Tentando conectar no banco...", flush=True)

        conn = fdb.connect(
            host='localhost',
            database=r"C:\Users\Aluno\Downloads\BANCO (1)\BANCO.FDB",
            user='SYSDBA',
            password='sysdba',
            charset='UTF8'
        )

        print(" CONECTOU COM SUCESSO", flush=True)
        return conn
    except Exception as e:
        print(f" ERRO REAL DO FIREBIRD: {e}", flush=True)
        return None


from view import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)