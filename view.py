import os
import threading
import random
from datetime import datetime, timedelta, timezone
import jwt
from flask import jsonify, request, make_response
from main import app, get_db_connection
from funcao import (verificar_senha, criptografar, checar_senha,
                    enviando_email, gerar_token, verificar_reuso_senha, gerar_codigo, validar_complexidade_senha)
from flask_cors import CORS

CORS(app, supports_credentials=True)

def verificar_token():
    token = request.cookies.get('access_token')

    if not token:
        return None

    try:
        dados = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )

        return dados

    except jwt.ExpiredSignatureError:
        return None

    except jwt.InvalidTokenError:
        return None

UPLOAD_PERFIL = os.path.join('uploads', 'usuarios')
if not os.path.exists(UPLOAD_PERFIL):
    os.makedirs(UPLOAD_PERFIL)


@app.route('/criar_usuario', methods=['POST'])
def criar_usuario():
    con = get_db_connection()
    if con is None:
        return jsonify({'erro': 'Erro ao conectar ao banco de dados'}), 500

    cur = con.cursor()
    try:

        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        telefone = request.form.get('telefone')


        id_cargo = request.form.get('id_cargo')
        if not id_cargo:
            id_cargo = 1


        if not nome or nome.strip() == "":
            return jsonify({'erro': 'Nome é obrigatório.'}), 400

        if not email or not senha:
            return jsonify({'erro': 'Email e Senha são obrigatórios.'}), 400


        erro_senha = verificar_senha(senha)
        if erro_senha:
            return jsonify({'erro': erro_senha}), 400


        cur.execute("SELECT id_usuario FROM usuario WHERE email = ?", (email,))
        if cur.fetchone():
            return jsonify({'erro': 'E-mail já cadastrado.'}), 409


        senha_hash = criptografar(senha)
        codigo_confirmacao = str(random.randint(100000, 999999))


        cur.execute("""
            INSERT INTO usuario (nome, email, telefone, senha, id_cargo, conta_confirmada, bloqueado, tentativas_login)
            VALUES (?, ?, ?, ?, ?, 0, 0, 0) RETURNING id_usuario
        """, (nome, email, telefone, senha_hash, id_cargo))

        id_usuario = cur.fetchone()[0]


        cur.execute("""
            INSERT INTO confirmar_codigo (id_usuario, codigo, utilizado) 
            VALUES (?, ?, 0)
        """, (id_usuario, codigo_confirmacao))


        foto = request.files.get('foto')
        if foto:
            foto.save(os.path.join(UPLOAD_PERFIL, f"perfil_{id_usuario}.jpg"))

        con.commit()


        assunto = "Ativação de Conta"
        corpo = f"Olá {nome}, seu código de ativação é: {codigo_confirmacao}"
        threading.Thread(target=enviando_email, args=(email, assunto, corpo)).start()

        return jsonify({
            "mensagem": "Usuário criado! Verifique seu e-mail.",
            "id_usuario": id_usuario,
        }), 201

    except Exception as e:
        if con: con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        if con: con.close()

@app.route('/confirmar_codigo', methods=['POST'])
def confirmar_codigo():
    con = get_db_connection()
    cur = con.cursor()
    try:

        dados = request.get_json(silent=True) or request.form

        id_user = dados.get('id_usuario')
        cod = dados.get('codigo')


        if not id_user or not cod or str(cod).strip() == "":
            return jsonify({"erro": "ID do usuário e Código são obrigatórios e não podem estar vazios!"}), 400


        id_user = int(id_user)


        cur.execute("""
            SELECT id_confirmacao 
            FROM confirmar_codigo 
            WHERE id_usuario = ? AND codigo = ? AND utilizado = 0
        """, (id_user, str(cod)))

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({"erro": "Código inválido, já utilizado ou expirado."}), 400


        cur.execute("UPDATE usuario SET conta_confirmada = 1 WHERE id_usuario = ?", (id_user,))
        cur.execute("UPDATE confirmar_codigo SET utilizado = 1 WHERE id_usuario = ? AND codigo = ?",
                    (id_user, str(cod)))

        con.commit()
        return jsonify({"mensagem": "Conta ativada com sucesso! Pode logar agora."}), 200

    except ValueError:
        return jsonify({"erro": "ID do usuário deve ser um número válido."}), 400
    except Exception as e:
        return jsonify({"erro": f"Erro interno: {str(e)}"}), 500
    finally:
        con.close()


@app.route('/login_usuario', methods=['POST'])
def login_usuario():
    con = get_db_connection()
    cur = con.cursor()

    try:

        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')
        senha = dados.get('senha')

        if not email or not senha:
            return jsonify({'erro': 'E-mail e senha são obrigatórios'}), 400


        cur.execute("""
            SELECT u.id_usuario, u.senha, u.nome, c.nome, u.conta_confirmada, u.bloqueado, u.tentativas_login 
            FROM usuario u 
            LEFT JOIN cargo c ON u.id_cargo = c.id_cargo 
            WHERE u.email = ?
        """, (email,))

        res = cur.fetchone()

        if not res:
            return jsonify({'erro': 'E-mail ou senha incorretos'}), 401

        id_user, hash_db, nome, cargo_nome, conf, bloq, tent = res


        if bloq == 1:
            return jsonify({'erro': 'Conta bloqueada por excesso de tentativas.'}), 403


        if conf == 0:
            return jsonify({'erro': 'E-mail não confirmado.'}), 403


        if checar_senha(senha, hash_db):

            cur.execute("UPDATE usuario SET tentativas_login = 0 WHERE id_usuario = ?", (id_user,))
            con.commit()

            token_data = {
                'id': id_user,
                'tipo': (cargo_nome or 'USUARIO').upper(),
                'exp': datetime.now(timezone.utc) + timedelta(hours=2)

            }

            token = jwt.encode(token_data, app.config['SECRET_KEY'], algorithm='HS256')

            resp = make_response(jsonify({
                'mensagem': 'Login realizado',
                'tipo': (cargo_nome or 'USUARIO').upper(),
                'nome': nome
            }), 200)

            resp.set_cookie(
                'access_token',
                token,
                httponly=True,
                secure=False,
                samesite='Lax',
                max_age=600
            )

            return resp

        else:

            novas_tentativas = tent + 1
            deve_bloquear = 1 if novas_tentativas >= 3 else 0

            cur.execute("""
                UPDATE usuario 
                SET tentativas_login = ?, bloqueado = ? 
                WHERE id_usuario = ?
            """, (novas_tentativas, deve_bloquear, id_user))
            con.commit()

            if deve_bloquear:
                return jsonify({'erro': 'Conta bloqueada após 3 tentativas.'}), 403

            return jsonify({'erro': f'Senha incorreta. Tentativa {novas_tentativas}/3'}), 401

    except Exception as e:
        return jsonify({'erro': f'Erro interno: {str(e)}'}), 500
    finally:
        con.close()

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'mensagem': 'Logout realizado'}), 200)
    resp.delete_cookie('access_token')
    return resp


@app.route('/usuarios', methods=['GET'])
def listar_usuarios():

    usuario = verificar_token()

    if not usuario:
        return jsonify({'erro': 'Não autorizado'}), 401

    if usuario['tipo'] != 'ADMIN':
        return jsonify({'erro': 'Apenas administradores'}), 403

    con = get_db_connection()
    cur = con.cursor()

    try:
        cur.execute("SELECT id_usuario, nome, email FROM usuario")
        usuarios = cur.fetchall()

        resultado = [
            {
                'id_usuario': u[0],
                'nome': u[1],
                'email': u[2]
            }
            for u in usuarios
        ]

        return jsonify(resultado), 200

    finally:
        con.close()

@app.route('/editar_usuario/<int:id_usuario>', methods=['PUT', 'POST'])
def editar_usuario(id_usuario):
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("SELECT senha, nome FROM usuario WHERE id_usuario = ?", (id_usuario,))
        res = cur.fetchone()
        if not res:
            return jsonify({'erro': 'Usuário não encontrado'}), 404

        hash_atual, nome_atual = res


        dados = request.get_json(silent=True) or request.form


        nome_novo = dados.get('nome', '').strip()
        senha_nova = dados.get('senha', '').strip()
        foto = request.files.get('foto')


        if not nome_novo:
            return jsonify({'erro': 'O nome é obrigatório e não pode conter apenas espaços.'}), 400


        if senha_nova:

            if not validar_complexidade_senha(senha_nova):
                return jsonify({'erro': 'Senha muito fraca! Use 8+ caracteres, com letras e números.'}), 400


            if verificar_reuso_senha(id_usuario, senha_nova, cur):
                return jsonify({'erro': 'Você já usou esta senha antes.'}), 400


            cur.execute("INSERT INTO historico_senhas (id_usuario, senha_antiga) VALUES (?, ?)",
                        (id_usuario, hash_atual))
            hash_atual = criptografar(senha_nova)


        cur.execute("""
            UPDATE usuario 
            SET nome = ?, senha = ? 
            WHERE id_usuario = ?
        """, (nome_novo, hash_atual, id_usuario))


        if foto:
            caminho_foto = os.path.join(UPLOAD_PERFIL, f"perfil_{id_usuario}.jpg")
            foto.save(caminho_foto)

        con.commit()
        return jsonify({'mensagem': 'Perfil atualizado com sucesso!'}), 200

    except Exception as e:

        return jsonify({'erro': f'Erro interno: {str(e)}'}), 500
    finally:
        con.close()

@app.route('/excluir_usuario/<int:id_usuario>', methods=['DELETE'])
def excluir_usuario(id_usuario):
    con = get_db_connection()
    cur = con.cursor()
    try:

        cur.execute("DELETE FROM CONFIRMAR_CODIGO WHERE ID_USUARIO = ?", (id_usuario,))


        cur.execute("DELETE FROM usuario WHERE id_usuario = ?", (id_usuario,))

        caminho_foto = os.path.join(UPLOAD_PERFIL, f"perfil_{id_usuario}.jpg")

        if os.path.exists(caminho_foto):
            os.remove(caminho_foto)

        con.commit()
        return jsonify({'mensagem': 'Usuário e dados vinculados excluídos!'}), 200
    except Exception as e:
        con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        con.close()

@app.route('/admin/buscar_nome', methods=['GET'])
def buscar_usuario():
    nome = request.args.get('nome', '')
    con = get_db_connection(); cur = con.cursor()
    cur.execute("SELECT id_usuario, nome, email FROM usuario WHERE UPPER(nome) LIKE UPPER(?)", (f'%{nome}%',))
    return jsonify([{'id': u[0], 'nome': u[1], 'email': u[2]} for u in cur.fetchall()]), 200


@app.route('/admin/desbloquear/<int:id_usuario>', methods=['POST'])
def desbloquear_usuario(id_usuario):

    usuario = verificar_token()

    if not usuario:
        return jsonify({'erro': 'Não autorizado'}), 401

    if usuario['tipo'] != 'ADMIN':
        return jsonify({'erro': 'Apenas administradores'}), 403

    con = get_db_connection()
    cur = con.cursor()

    try:

        cur.execute(
            "UPDATE usuario SET bloqueado = 0, tentativas_login = 0 WHERE id_usuario = ?",
            (id_usuario,)
        )

        con.commit()

        return jsonify({
            'mensagem': 'Desbloqueado!'
        }), 200

    except Exception as e:

        con.rollback()

        return jsonify({
            'erro': str(e)
        }), 500

    finally:
        con.close()


@app.route('/solicitar_recuperacao', methods=['POST'])
def solicitar_recuperacao():
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')

        cur.execute("SELECT id_usuario FROM usuario WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            return jsonify({'erro': 'E-mail não encontrado'}), 404

        codigo = str(random.randint(100000, 999999))


        expiracao = datetime.now() + timedelta(minutes=10)

        cur.execute("""
            INSERT INTO recuperar_senha (id_usuario, codigo, expiracao, utilizado) 
            VALUES (?, ?, ?, 0)
        """, (user[0], codigo, expiracao))

        con.commit()


        threading.Thread(target=enviando_email, args=(email, "Recuperar", f"Cód: {codigo}")).start()

        return jsonify({"mensagem": "E-mail enviado!"}), 200
    except Exception as e:
        return jsonify({"erro": f"Erro interno: {str(e)}"}), 500
    finally:
        con.close()


@app.route('/redefinir_senha', methods=['POST'])
def redefinir_senha():
    con = get_db_connection()
    cur = con.cursor()
    try:

        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')
        codigo = dados.get('codigo')
        nova_senha = dados.get('nova_senha')


        cur.execute("SELECT id_usuario FROM usuario WHERE email = ?", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({'erro': 'Usuário não encontrado'}), 404

        id_u = usuario[0]

        agora = datetime.now()

        cur.execute("""
            SELECT id_recuperacao 
            FROM recuperar_senha 
            WHERE id_usuario = ? AND codigo = ? AND utilizado = 0 AND expiracao > ?
        """, (id_u, codigo, agora))

        if not cur.fetchone():
            return jsonify({'erro': 'Código inválido ou expirado'}), 400

        if not validar_complexidade_senha(nova_senha):
            return jsonify({'erro': 'Senha fraca'}), 400


        senha_cripto = criptografar(nova_senha)
        cur.execute("""
            UPDATE usuario 
            SET senha = ?, bloqueado = 0, tentativas_login = 0 
            WHERE id_usuario = ?
        """, (senha_cripto, id_u))


        cur.execute("""
            UPDATE recuperar_senha 
            SET utilizado = 1 
            WHERE id_usuario = ? AND codigo = ?
        """, (id_u, codigo))

        con.commit()
        return jsonify({"mensagem": "Senha alterada com sucesso!"}), 200

    except Exception as e:
        return jsonify({"erro": f"Erro interno: {str(e)}"}), 500
    finally:
        con.close()

        def verificar_token():
            token = request.cookies.get('access_token')

            print("COOKIE RECEBIDO:", token)  # 👈 DEBUG

            if not token:
                return None

            try:
                dados = jwt.decode(
                    token,
                    app.config['SECRET_KEY'],
                    algorithms=['HS256']
                )

                print("TOKEN OK:", dados)  # 👈 DEBUG
                return dados

            except Exception as e:
                print("ERRO TOKEN:", e)
                return None
