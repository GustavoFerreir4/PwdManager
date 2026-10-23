import core
from getpass import getpass as secret
import os

def login(username:str, masterPwd) -> bool:
    auth = core.Authenticador()
    db = core.Banco()

    if not db.usuario_existe(username):
        return False

    query = db.buscar_usuario(username)
    salt = query[1]
    token = query[2]
    if auth.destravar_cofre(sal=salt, token_de_verificacao=token, senha_mestra=masterPwd):
        return True
    else:
        return False


def register(username:str, masterPwd:str):
    auth = core.Authenticador()
    db = core.Banco()

    if db.usuario_existe(username):
        return None

    sault, token = auth.criar_segredos_do_usuario(masterPwd)

    db.salvar_usuario(username, sault, token)

    return True
    #para testar a saída:
    # print(sault)
    # print(token)
    # print(db.buscar_usuario(username))

def showActions(section:int, editar:bool=False):
    home = """

    1- login
    2- registrar
    3- sair

    """

    credenciais = """

    1- listar credenciais
    2- registrar nova credencial
    3- editar credencial
    4- excluir credencial
    5- sair (login)

    """

    editar = """

    """

    if section == 1:
        return print(home)
    elif section == 2:
        return print(credenciais)
    elif editar:
        return print(editar)
        
def listar_credenciais():
    pass

def registrar_credencial():
    pass

def editar_credencial():
    pass

def excluir_credencial():
    pass

i = 0

print("BEM VINDO(A) AO PwdManager.")
showActions(1) 
action = int(input())

while action not in (1, 2, 3):
    os.system("cls")
    showActions(1) 
    action = int(input())

if action == 3:
    os.close()

if action == 2:
    print("Informe dados do usuário.")
    username = input("usuário: ")
    masterPwd = secret("senha: ")
    if register(username, masterPwd):
        print("Usuário registrado com sucesso!")
        login(username, masterPwd)
    else:
        print("Este nome de usuário já existe.")

if action == 1:
    print("Informe os dados do usuário:")
    username = input("usuário: ")
    masterPwd = secret("senha: ")
    if login(username, masterPwd):
        print("usuário logado com sucesso.")
        showActions(2)
    else:
        print("Senha incorreta.")
sla = core.PwdManager().