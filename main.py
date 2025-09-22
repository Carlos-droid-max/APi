from flask import Flask, make_response, jsonify, request
import pandas as pd
import os
from argon2 import PasswordHasher


app = Flask(__name__)

#Empresa

ARQUIVO_CSV = 'cnpj.csv'
ARQUIVO_ANOM_CSV ='cnpj_anom.csv'

if os.path.exists(ARQUIVO_CSV) and os.path.getsize(ARQUIVO_CSV) > 0 and os.path.exists(ARQUIVO_ANOM_CSV) and os.path.getsize(ARQUIVO_ANOM_CSV):
    dfEmpresa = pd.read_csv(ARQUIVO_CSV)
    dfEmpresaAnom = pd.read_csv(ARQUIVO_ANOM_CSV)
else:
    dfEmpresa = pd.DataFrame(columns=['cnpj'])
    dfEmpresaAnom = pd.DataFrame(columns=['cnpj'])


@app.route('/cnpj', methods=['POST'])
def cnpj():
    #“esta função vai usar a variável dfEmpresa que está fora da função, não criar uma local”.
    global dfEmpresa
    global dfEmpresaAnom
    dados = request.json
    cnpj = dados.get('cnpj')
    
    if cnpj is None:
        return jsonify({'error' : 'CNPJ não fornecido'})
    
    resp = 'CNPJ_' + str(len(dfEmpresa)+1).zfill(4)
    dfEmpresa.loc[len(dfEmpresa)] = [cnpj]
    dfEmpresaAnom.loc[len(dfEmpresa)] = [resp]

    # Salva o DataFrame atualizado no CSV
    dfEmpresa.to_csv(ARQUIVO_CSV, sep=';', index=False)
    dfEmpresaAnom.to_csv(ARQUIVO_ANOM_CSV, sep=';', index=False)




ph = PasswordHasher()

ARQUIVO_Empresa_Cadastro_CSV = 'empresa_cadastro.csv'
ARQUIVO_Empresa_Cadastro_ANOM_CSV = 'empresa_cadastro_anom.csv'

if os.path.exists(ARQUIVO_Empresa_Cadastro_CSV) and os.path.getsize(ARQUIVO_Empresa_Cadastro_CSV) > 0 and os.path.exists(ARQUIVO_Empresa_Cadastro_ANOM_CSV) and os.path.getsize(ARQUIVO_Empresa_Cadastro_ANOM_CSV) > 0:
    dfCadastro = pd.read_csv(ARQUIVO_Empresa_Cadastro_CSV)
    dfCadastroAnom = pd.read_csv(ARQUIVO_Empresa_Cadastro_ANOM_CSV)
else:
    dfCadastro = pd.DataFrame(columns=['email', 'senha'])
    dfCadastroAnom = pd.DataFrame(columns=['email', 'senha'])

@app.route('/empresa/cadastro', methods=['POST'])
def empresa_cadastro():

    global dfCadastro
    global dfCadastroAnom
    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')

    if senha is None or email is None:
        return jsonify({'error' : 'Dados não fornecidos'})
    
    hash_senha = ph.hash(senha)
    resp = 'Empre_Email_' + str(len(dfCadastro)+1).zfill(4)

    nova_linha = {'email': email, 'senha': hash_senha}
    dfCadastro = pd.concat([dfCadastro, pd.DataFrame([nova_linha])], ignore_index=True)
    nova_linha_anom = {'email': resp, 'senha': hash_senha}
    dfCadastroAnom = pd.concat([dfCadastroAnom, pd.DataFrame([nova_linha_anom])], ignore_index=True)

    dfCadastro.to_csv(ARQUIVO_Empresa_Cadastro_CSV, sep=';', index=False)
    dfCadastroAnom.to_csv(ARQUIVO_Empresa_Cadastro_ANOM_CSV, sep=';', index=False)

    return jsonify(resp + '  ;  ' + hash_senha)

@app.route('/empresa/login', methods=['POST'])
def empresa_verificar():

    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')

    if senha is None or email is None:
        return jsonify({'error' : 'Dados não fornecidos'})
    
    email_linha = None

    with open(ARQUIVO_Empresa_Cadastro_CSV, 'r') as arquivo:
        for indce, linha in enumerate(arquivo):
            if indce == 0:
                continue
            if linha.split(';')[0] == email:
                email_linha = indce + 1
                break

    if email_linha is None:
        return jsonify(False)

    
    with open(ARQUIVO_Empresa_Cadastro_CSV, 'r') as f:  # Abre o arquivo para leitura
        for indice, linha in enumerate(f):
            # enumerate retorna (0, primeira_linha), (1, segunda_linha), etc.
            # Subtraímos 1 do numero_linha para comparar com o índice começando do 0.

            if indice == 0:
                continue

            if indice == email_linha - 1:
                senha_hash = linha.split(';')[1].strip()

    if ph.verify(senha_hash, senha):
        return jsonify(True)
    else:
        return jsonify(False)
    

ARQUIVO_Empresa_Telefones_CSV = 'empresa_telefones.csv'
ARQUIVO_Empresa_Telefones_ANOM_CSV = 'empresa_telefones_anom.csv'

if os.path.exists(ARQUIVO_Empresa_Telefones_CSV) and os.path.getsize(ARQUIVO_Empresa_Telefones_CSV) > 0 and os.path.exists(ARQUIVO_Empresa_Telefones_ANOM_CSV) and os.path.getsize(ARQUIVO_Empresa_Telefones_ANOM_CSV) > 0:
    dfEmpresaTelefones = pd.read_csv(ARQUIVO_Empresa_Telefones_CSV)
    dfEmpresaTelefonesAnom = pd.read_csv(ARQUIVO_Empresa_Telefones_ANOM_CSV)
else:
    dfEmpresaTelefones = pd.DataFrame(columns=['telefone'])
    dfEmpresaTelefonesAnom = pd.DataFrame(columns=['telefone'])
    
@app.route('/empresa/telefone', methods=['POST'])
def empresa_telefone():

    global dfEmpresaTelefones
    global dfEmpresaTelefonesAnom
    dados = request.json
    telefone = dados.get('telefone')

    if telefone is None:
        return jsonify({'error' : 'Telefone não fornecido'})
    

    resp = 'Empre_Tel_' + str(len(dfEmpresaTelefones)+1).zfill(4)

    dfEmpresaTelefones.loc[len(dfEmpresaTelefones)] = [telefone]
    dfEmpresaTelefonesAnom.loc[len(dfEmpresaTelefonesAnom)] = [resp]


    dfEmpresaTelefones.to_csv(ARQUIVO_Empresa_Telefones_CSV, sep=';', index=False)
    dfEmpresaTelefonesAnom.to_csv(ARQUIVO_Empresa_Telefones_ANOM_CSV, sep=';', index=False)



# ----------- Funcionários ---------------

ARQUIVO_Funcionario_Cadastro_CSV = 'funcionario_cadastro.csv'
ARQUIVO_Funcionario_Cadastro_ANOM_CSV = 'funcionario_cadastro_anom.csv'

if os.path.exists(ARQUIVO_Funcionario_Cadastro_CSV) and os.path.getsize(ARQUIVO_Funcionario_Cadastro_CSV) > 0 and os.path.exists(ARQUIVO_Funcionario_Cadastro_ANOM_CSV) and os.path.getsize(ARQUIVO_Funcionario_Cadastro_ANOM_CSV) > 0:
    dfFuncionarioCadastro = pd.read_csv(ARQUIVO_Funcionario_Cadastro_CSV)
    dfFuncionarioCadastroAnom = pd.read_csv(ARQUIVO_Funcionario_Cadastro_ANOM_CSV)
else:
    dfFuncionarioCadastro = pd.DataFrame(columns=['email', 'senha'])
    dfFuncionarioCadastroAnom = pd.DataFrame(columns=['email', 'senha'])

@app.route('/funcionario/cadastro', methods=['POST'])
def funcionario_cadastro():

    global dfFuncionarioCadastro
    global dfEmpresaTelefonesAnom
    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')

    if senha is None or email is None:
        return jsonify({'error' : 'Dados não fornecidos'})
    
    hash_senha = ph.hash(senha)
    resp = 'Funcio_Email_' + str(len(dfFuncionarioCadastro)+1).zfill(4)

    nova_linha = {'email': email, 'senha': hash_senha}
    dfFuncionarioCadastro = pd.concat([dfFuncionarioCadastro, pd.DataFrame([nova_linha])], ignore_index=True)
    nova_linha_anom = {'email': resp, 'senha': hash_senha}
    dfFuncionarioCadastroAnom = pd.concat([dfFuncionarioCadastroAnom, pd.DataFrame([nova_linha_anom])], ignore_index=True)

    dfFuncionarioCadastro.to_csv(ARQUIVO_Funcionario_Cadastro_CSV, sep=';', index=False)
    dfFuncionarioCadastroAnom.to_csv(ARQUIVO_Funcionario_Cadastro_ANOM_CSV, sep=';', index=False)

    return jsonify(hash_senha)



@app.route('/funcionario/login', methods=['POST'])
def funcionario_verificar():

    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')

    if senha is None or email is None:
        return jsonify({'error' : 'Dados não fornecidos'})
    
    email_linha = None

    with open(ARQUIVO_Funcionario_Cadastro_CSV, 'r') as arquivo:
        for indice, linha in enumerate(arquivo):
            if indice == 0:
                continue
            if linha.split(";")[0] == email:
                email_linha = indice + 1
                break

    if email_linha is None:
        return jsonify(False)

    
    with open(ARQUIVO_Funcionario_Cadastro_CSV, 'r') as f:  # Abre o arquivo para leitura
        for indice, linha in enumerate(f):
            # enumerate retorna (0, primeira_linha), (1, segunda_linha), etc.
            # Subtraímos 1 do numero_linha para comparar com o índice começando do 0.

            if indice == 0:
                continue

            if indice == email_linha - 1:
                senha_hash = linha.split(';')[1].strip()

    if ph.verify(senha_hash, senha):
        return jsonify(True)
    else:
        return jsonify(False)
    

ARQUIVO_Funcionario_Telefones_CSV = 'funcionarios_telefones.csv'
ARQUIVO_Funcionario_Telefones_ANOM_CSV = 'funcionarios_telefones_anom.csv'

if os.path.exists(ARQUIVO_Funcionario_Telefones_CSV) and os.path.getsize(ARQUIVO_Funcionario_Telefones_CSV) > 0 and os.path.exists(ARQUIVO_Funcionario_Telefones_ANOM_CSV) and os.path.getsize(ARQUIVO_Funcionario_Telefones_ANOM_CSV) > 0 :
    dfFuncionarioCadastro = pd.read_csv(ARQUIVO_Funcionario_Telefones_CSV)
    dfFuncionarioCadastroAnom = pd.read_csv(ARQUIVO_Funcionario_Telefones_ANOM_CSV)
else:
    dfFuncionarioTelefones = pd.DataFrame(columns=['telefone'])
    dfFuncionarioTelefonesAnom = pd.DataFrame(columns=['telefone'])
    
@app.route('/funcionario/telefone', methods=['POST'])
def funcionario_telefone():

    global dfFuncionarioTelefones
    global dfFuncionarioTelefonesAnom
    dados = request.json
    telefone = dados.get('telefone')

    if telefone is None:
        return jsonify({'error' : 'Telefone não fornecido'})

    dfFuncionarioTelefones.loc[len(dfFuncionarioTelefones)] = [telefone]

    resp = 'Funcio_Tel_' + str(len(dfFuncionarioTelefones)+1).zfill(4)
    dfFuncionarioTelefones.loc[len(dfFuncionarioTelefones)] = [resp]


    dfFuncionarioTelefones.to_csv(ARQUIVO_Funcionario_Telefones_CSV, sep=';', index=False)
    dfFuncionarioTelefonesAnom.to_csv(ARQUIVO_Funcionario_Telefones_ANOM_CSV, sep=';', index=False)



#------------------ Adiministrador ---------------------


ARQUIVO_Admin_Cadastro_CSV = 'admin_login.csv'
ARQUIVO_Admin_Cadastro_ANOM_CSV = 'admin_login_anom.csv'

if os.path.exists(ARQUIVO_Admin_Cadastro_CSV) and os.path.getsize(ARQUIVO_Admin_Cadastro_CSV) > 0 and os.path.exists(ARQUIVO_Admin_Cadastro_ANOM_CSV) and os.path.getsize(ARQUIVO_Admin_Cadastro_ANOM_CSV) > 0:
    dfAdminCadastro = pd.read_csv(ARQUIVO_Admin_Cadastro_CSV)
    dfAdminCadastroAnom = pd.read_csv(ARQUIVO_Admin_Cadastro_ANOM_CSV)
else:
    dfAdminCadastro = pd.DataFrame(columns=['email', 'senha'])
    dfAdminCadastroAnom = pd.DataFrame(columns=['email', 'senha'])

@app.route('/admin/cadastro', methods=['POST'])
def admin_cadastro():

    global dfAdminCadastro
    global dfAdminCadastroAnom
    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')

    if senha is None or email is None:
        return jsonify({'error' : 'Dados não fornecidos'})
    
    hash_senha = ph.hash(senha)
    resp = 'Admin_Email_' + str(len(dfAdminCadastro)+1).zfill(4)

    nova_linha = {'email': email, 'senha': hash_senha}
    dfAdminCadastro = pd.concat([dfAdminCadastro, pd.DataFrame([nova_linha])], ignore_index=True)
    nova_linhaAnom = {'email': resp, 'senha': hash_senha}
    dfAdminCadastroAnom = pd.concat([dfAdminCadastroAnom, pd.DataFrame([nova_linhaAnom])], ignore_index=True)

    dfAdminCadastro.to_csv(ARQUIVO_Admin_Cadastro_CSV, sep=';', index=False)
    dfAdminCadastroAnom.to_csv(ARQUIVO_Admin_Cadastro_ANOM_CSV, sep=';', index=False)

    return jsonify(hash_senha)

@app.route('/admin/login', methods=['POST'])
def admin_verificar():

    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')

    if senha is None or email is None:
        return jsonify({'error' : 'Dados não fornecidos'})
    
    email_linha = None

    with open(ARQUIVO_Admin_Cadastro_CSV, 'r') as arquivo:
        for indice, linha in enumerate(arquivo):
            if indice == 0:
                continue
            if linha.split(";")[0] == email:
                email_linha = indice + 1
                break

    if email_linha is None:
        return jsonify(False)

    
    with open(ARQUIVO_Admin_Cadastro_CSV, 'r') as f:  # Abre o arquivo para leitura
        for indice, linha in enumerate(f):
            # enumerate retorna (0, primeira_linha), (1, segunda_linha), etc.
            # Subtraímos 1 do numero_linha para comparar com o índice começando do 0.

            if indice == 0:
                continue

            if indice == email_linha - 1:
                senha_hash = linha.split(';')[1].strip()

    if ph.verify(senha_hash, senha):
        return jsonify(True)
    else:
        return jsonify(False)
    
@app.route('/limpeza_de_tudo', methods=['POST'])
def limpeza():
    global dfEmpresa, dfCadastro, dfTelefones, dfFuncionarioCadastro, dfFuncionarioTelefones, dfAdminCadastro

    dfEmpresa = dfEmpresa.iloc[0:0]   # mantém só as colunas
    dfEmpresa.to_csv(ARQUIVO_CSV, index=False)

    dfCadastro = dfCadastro.iloc[0:0]   # mantém só as colunas
    dfCadastro.to_csv(ARQUIVO_Empresa_Cadastro_CSV, index=False)

    dfTelefones = dfTelefones.iloc[0:0]   # mantém só as colunas
    dfTelefones.to_csv(ARQUIVO_Empresa_Telefones_CSV, index=False)
    

    dfFuncionarioCadastro = dfFuncionarioCadastro.iloc[0:0]   # mantém só as colunas
    dfFuncionarioCadastro.to_csv(ARQUIVO_Funcionario_Cadastro_CSV, index=False)

    dfFuncionarioTelefones = dfFuncionarioTelefones.iloc[0:0]   # mantém só as colunas
    dfFuncionarioTelefones.to_csv(ARQUIVO_Funcionario_Telefones_CSV, index=False)

    dfAdminCadastro = dfAdminCadastro.iloc[0:0]   # mantém só as colunas
    dfAdminCadastro.to_csv(ARQUIVO_Admin_Cadastro_CSV, index=False)

    
    return jsonify('Todos os arquivos foram esvaziados')


if __name__ == '__main__':
    app.run(debug=True)
