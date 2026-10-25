import base64
import json
import os
import sqlite3

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class Autenticador():

    def __init__(self):
        """ se conseguirmos descriptografar TEXTO_DE_VERIFICACAO, é porque a senha mestra está certa."""

        self._TEXTO_DE_VERIFICACAO = b"V4ult-ok4y!"
        self._COMPRIMENTO_MINIMO = 8
        return

    def gerar_chave(self, senha_mestra: str, sal: bytes) -> bytes:
        scrypt = Scrypt(salt=sal, length=32, n=2**15, r=8, p=1)
        chave_bruta = scrypt.derive(senha_mestra.encode("utf-8"))
        # O Fernet exige a chave em base64 "url-safe"
        return base64.urlsafe_b64encode(chave_bruta)

    def criar_segredos_do_usuario(self, senha_mestra: str):
        """
        Usado no CADASTRO. Devolve o que deve ser guardado na tabela de usuários:
        - sal: bytes aleatórios (não é secreto, só precisa ser único)
        - token_de_verificacao: o TEXTO_DE_VERIFICACAO já criptografado
        """
        sal = os.urandom(16)
        fernet = Fernet(self.gerar_chave(senha_mestra, sal))
        token_de_verificacao = fernet.encrypt(self._TEXTO_DE_VERIFICACAO)
        return sal, token_de_verificacao

    def destravar_cofre(self, senha_mestra: str, sal: bytes, token_de_verificacao: bytes) -> Fernet:
        """
        Usado no LOGIN. Recria a chave e testa se ela abre o token de verificação.
        Senha certa  -> devolve o objeto Fernet (a "chave na mão", só na memória).
        Senha errada -> devolve None.
        """
        fernet = Fernet(self.gerar_chave(senha_mestra, sal))
        try:
            fernet.decrypt(token_de_verificacao)
            return fernet
        except InvalidToken:  # chave diferente => o Fernet recusa
            return None    

class Banco:
    def __init__(self, arquivo="vault.db"):
        self.arquivo = arquivo
        self._criar_tabelas()

    def _conectar(self):
        conexao = sqlite3.connect(self.arquivo)
        conexao.execute("PRAGMA foreign_keys = ON")  # ativa a chave estrangeira
        return conexao

    def _criar_tabelas(self):
        conexao = self._conectar()
        conexao.executescript("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                sal BLOB NOT NULL,
                token_de_verificacao BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credenciais (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                titulo TEXT UNIQUE NOT NULL,
                dados_criptografados BLOB NOT NULL
            );
        """)
        conexao.commit()
        conexao.close()

    def usuario_existe(self, nome: str) -> bool:
        conexao = self._conectar()
        # "?" = parâmetro seguro (evita SQL injection)
        linha = conexao.execute("SELECT 1 FROM usuarios WHERE nome = ?", (nome,)).fetchone()
        conexao.close()
        return linha is not None

    def salvar_usuario(self, nome: str, sal: bytes, token_de_verificacao: bytes):
        conexao = self._conectar()
        conexao.execute(
            "INSERT INTO usuarios (nome, sal, token_de_verificacao) VALUES (?, ?, ?)",
            (nome, sal, token_de_verificacao),
        )
        conexao.commit()
        conexao.close()

    def buscar_usuario(self, nome: str) -> tuple:
        """Devolve (id, sal, token_de_verificacao) ou None."""
        conexao = self._conectar()
        linha = conexao.execute(
            "SELECT id, sal, token_de_verificacao FROM usuarios WHERE nome = ?", (nome,)
        ).fetchone()
        conexao.close()
        return linha

    # ----- credenciais -----

    def salvar_credencial(self, usuario_id: int, titulo: str, dados_criptografados: bytes):
        conexao = self._conectar()
        conexao.execute(
            "INSERT INTO credenciais (usuario_id, titulo, dados_criptografados) VALUES (?, ?, ?)",
            (usuario_id, titulo, dados_criptografados),
        )
        conexao.commit()
        conexao.close()

    def listar_credenciais(self, usuario_id: int):
        """Devolve lista de (id, titulo, dados_criptografados)."""

        conexao = self._conectar()
        linhas = conexao.execute(
            "SELECT id, titulo, dados_criptografados FROM credenciais WHERE usuario_id = ?",
            (usuario_id)
        ).fetchall()
        conexao.close()
        return linhas

    def buscar_credencial(self, titulo:str):
        conexao = self._conectar()
        linha = conexao.execute(
            "SELECT id, titulo FROM credenciais WHERE titulo = ?",
            (titulo,),
        ).fetchone()
        conexao.close()
        return linha

class PwdManager:
    """ 
        API interna para a interface gráfica 
        - Sessão do usuário
        - CRUD
    
    """
    def __init__(self, banco):
        self._auth = Autenticador()
        self._banco = Banco()
        self._usuario_id = None
        self._fernet = None          # a chave, só na memória

    def cadastrar(self, nome:str, senha:str) -> bool:   # levanta UsuarioJaExiste
        if self._banco.usuario_existe(nome):
            raise Exception("Este usuário já existe.")

        sal, token = self._auth.criar_segredos_do_usuario(senha)
        self._banco.salvar_usuario(
            nome=nome,
            sal=sal,
            token_de_verificacao=token
        )

        return True
    
    def entrar(self, nome, senha) -> bool:     # levanta [SenhaIncorreta, UsuárioInexistente]
        if not self._banco.usuario_existe(nome):
            raise Exception("Este usuário não existe.")
        
        self._usuario_id, sal, token = self._banco.buscar_usuario(nome=nome)
        self._fernet = self._auth.destravar_cofre(sal=sal, senha_mestra=senha, token_de_verificacao=token)   

        if self._fernet:
            return True
        else:
            return False

    def sair(self):                         # bloqueia o cofre
        self._usuario_id = None
        self._fernet = None

    def _adicionar(self, titulo:str, dados: dict) -> bool:
        """
            Adicionar credencial associada ao usuário da sessão se titulo não existir.
            - título da credencial
            - dict({'site': str, 'senha': str})
        """
        if not self._sessao_valida():
            raise Exception("Sessão não é válida.")

        if self._credencial_existe(titulo_credencial=titulo):
            raise Exception("Já existe uma credencial com este nome.")

        dados_criptografados = self.criptografar_credencial(fernet=self._fernet, credencial=dados)
        self._banco.salvar_credencial(usuario_id=self._usuario_id, titulo=titulo, dados_criptografados=dados_criptografados)
        
        return True


    def _listar(self) -> list[dict]:    # já descriptografado
        if not self._sessao_valida():
            raise Exception("Sessão não é válida.")

        registros = self._banco.listar_credenciais(usuario_id=self._usuario_id)
        credenciais = list()

        for registro in registros:
            dados_descriptografados = self.descriptografar_credencial(self._fernet, registro[2])
            credenciais.append({'titulo': registro[1], 'site': dados_descriptografados['site'], 'senha': dados_descriptografados['senha']})

        print(credenciais)

    
    def _remover(self, credencial_id): ...

    def criptografar_credencial(self, fernet: Fernet, credencial: dict) -> bytes:
        """dict -> texto JSON -> bytes -> criptografado."""
        texto_json = json.dumps(credencial)
        return fernet.encrypt(texto_json.encode("utf-8"))

    def descriptografar_credencial(self, fernet: Fernet, dados_criptografados: bytes) -> dict:
        """criptografado -> bytes -> texto JSON -> dict."""
        texto_json = fernet.decrypt(dados_criptografados).decode("utf-8")
        return json.loads(texto_json)

    def verifica_comprimento_minimo_de_credencial(self, senha:str) -> bool:
        """
            Deveria seguir padrão estabelecido na configuração da aplicação.
        """
        if len(senha) >= self._COMPRIMENTO_MINIMO:
            return True

    def _sessao_valida(self):
        if self._usuario_id and self._fernet:
            return True
        return False

    def _credencial_existe(self, titulo_credencial:str) -> bool:
        existeRegistro = bool(self._banco.buscar_credencial(titulo=titulo_credencial))
        if existeRegistro:
            return True
        else:
            return False
        



