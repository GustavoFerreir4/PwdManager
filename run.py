import app.core as core


def login():
    auth = core.Authenticador()
    db = core.Banco()

    print("Informe usuário e senha para o aplicativo:")
    username = input("Informe usuário para o aplicativo: ")
    masterPassword = input("Informe a senha: ")

    if not db.usuario_existe(username):
        return None

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
        return home
    elif section == 2:
        return credenciais
    elif editar:
        return editar
        


i = 0

while True:
    if i == 0:
        showActions(1)  
    action = int(input("option: "))
