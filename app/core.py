"""
core.py — núcleo do gerenciador de senhas (sem interface gráfica).

Camadas:
    Autenticador         -> criptografia: senha mestra -> chave (Scrypt) -> Fernet
    Banco                -> persistência (SQLite); credenciais sempre filtradas por usuário
    GerenciadorDeSenhas  -> API interna para a GUI: sessão + CRUD

Requer Python 3.10+.
"""

import base64
import json
import os
import sqlite3
from contextlib import closing
from typing import NamedTuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Se conseguirmos descriptografar este texto, é porque a senha mestra está certa.
TEXTO_DE_VERIFICACAO = b"V4ult-ok4y!"

# A senha mestra é a única coisa que protege o cofre: o piso precisa ser alto.
COMPRIMENTO_MINIMO_SENHA_MESTRA = 12

# Guardada em PRAGMA user_version. Aumente ao mudar as tabelas.
VERSAO_DO_ESQUEMA = 2


# ---------------------------------------------------------------------------
# EXCEÇÕES — a GUI decide como mostrar cada erro (sem comparar texto)
# ---------------------------------------------------------------------------

class ErroDoCofre(Exception):
    """Base de todos os erros levantados pelo core."""


class UsuarioJaExiste(ErroDoCofre):
    pass


class CredenciaisInvalidas(ErroDoCofre):
    """Usuário inexistente OU senha errada (de propósito, a mensagem é a mesma)."""


class SenhaMestraFraca(ErroDoCofre):
    pass


class DadosInvalidos(ErroDoCofre):
    pass


class CofreBloqueado(ErroDoCofre):
    """Operação pedida sem sessão ativa."""


class CredencialJaExiste(ErroDoCofre):
    pass


class CredencialInexistente(ErroDoCofre):
    pass


class CredencialAdulterada(ErroDoCofre):
    """O registro no banco foi alterado ou corrompido fora do app."""


class EsquemaIncompativel(ErroDoCofre):
    """O arquivo do banco foi criado por uma versão antiga do app."""


# ---------------------------------------------------------------------------
# CRIPTOGRAFIA
# ---------------------------------------------------------------------------

class ParametrosKdf(NamedTuple):
    """
    Custo do Scrypt. Fica salvo POR USUÁRIO, então dá para aumentar o custo
    nos novos cadastros sem impedir os usuários antigos de entrar.
    """
    n: int = 2**17   # custo de CPU/memória (~128 MiB com r=8)
    r: int = 8
    p: int = 1


class Autenticador:

    def __init__(self, parametros_kdf: ParametrosKdf | None = None):
        # Parâmetros usados nos NOVOS cadastros
        self._parametros_kdf = parametros_kdf or ParametrosKdf()

    def gerar_chave(self, senha_mestra: str, sal: bytes, parametros_kdf: ParametrosKdf) -> bytes:
        """Mesma senha + mesmo sal + mesmos parâmetros -> sempre a mesma chave."""
        scrypt = Scrypt(
            salt=sal,
            length=32,
            n=parametros_kdf.n,
            r=parametros_kdf.r,
            p=parametros_kdf.p,
        )
        chave_bruta = scrypt.derive(senha_mestra.encode("utf-8"))
        # O Fernet exige a chave em base64 "url-safe"
        return base64.urlsafe_b64encode(chave_bruta)

    def criar_segredos_do_usuario(self, senha_mestra: str) -> tuple[bytes, bytes, ParametrosKdf]:
        """
        Usado no CADASTRO. Devolve o que deve ser guardado na tabela de usuários:
        - sal: bytes aleatórios (não é secreto, só precisa ser único)
        - token_de_verificacao: o TEXTO_DE_VERIFICACAO já criptografado
        - parametros_kdf: custo usado para derivar a chave
        """
        sal = os.urandom(16)
        parametros_kdf = self._parametros_kdf
        fernet = Fernet(self.gerar_chave(senha_mestra, sal, parametros_kdf))
        token_de_verificacao = fernet.encrypt(TEXTO_DE_VERIFICACAO)
        return sal, token_de_verificacao, parametros_kdf

    def destravar_cofre(
        self,
        senha_mestra: str,
        sal: bytes,
        token_de_verificacao: bytes,
        parametros_kdf: ParametrosKdf,
    ) -> Fernet | None:
        """
        Usado no LOGIN. Recria a chave e testa se ela abre o token de verificação.
        Senha certa  -> devolve o objeto Fernet (a "chave na mão", só na memória).
        Senha errada -> devolve None.
        """
        fernet = Fernet(self.gerar_chave(senha_mestra, sal, parametros_kdf))
        try:
            fernet.decrypt(token_de_verificacao)
        except InvalidToken:  # chave diferente => o Fernet recusa
            return None
        return fernet


# ---------------------------------------------------------------------------
# BANCO DE DADOS
# ---------------------------------------------------------------------------

ESQUEMA = f"""
    CREATE TABLE usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL UNIQUE,
        sal BLOB NOT NULL,
        token_de_verificacao BLOB NOT NULL,
        kdf_n INTEGER NOT NULL,
        kdf_r INTEGER NOT NULL,
        kdf_p INTEGER NOT NULL
    );
    CREATE TABLE credenciais (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        titulo TEXT NOT NULL,
        dados_criptografados BLOB NOT NULL,
        UNIQUE (usuario_id, titulo)
    );
    PRAGMA user_version = {VERSAO_DO_ESQUEMA};
"""


class Usuario(NamedTuple):
    id: int
    sal: bytes
    token_de_verificacao: bytes
    parametros_kdf: ParametrosKdf


def _e_violacao_de_unicidade(erro: sqlite3.IntegrityError) -> bool:
    return "UNIQUE constraint failed" in str(erro)


class Banco:
    """Recebe o caminho de um ARQUIVO (não use ':memory:': cada conexão seria um banco novo)."""

    def __init__(self, arquivo: str = "vault.db"):
        self.arquivo = arquivo
        self._preparar_esquema()
        os.chmod(self.arquivo, 0o600)  # só o dono lê/escreve (no Windows não tem efeito)

    def _conectar(self) -> sqlite3.Connection:
        conexao = sqlite3.connect(self.arquivo)
        conexao.row_factory = sqlite3.Row            # acessa colunas pelo nome
        conexao.execute("PRAGMA foreign_keys = ON")  # ativa a chave estrangeira
        return conexao

    def _preparar_esquema(self):
        # closing() fecha a conexão; "with conexao" faz commit (ou rollback se der erro)
        with closing(self._conectar()) as conexao, conexao:
            versao = conexao.execute("PRAGMA user_version").fetchone()[0]
            if versao == VERSAO_DO_ESQUEMA:
                return

            tabela_antiga = conexao.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'usuarios'"
            ).fetchone()
            if tabela_antiga:
                raise EsquemaIncompativel(
                    "Este banco foi criado por uma versão antiga. "
                    "Apague o arquivo (se for só de testes) ou migre os dados."
                )

            conexao.executescript(ESQUEMA)

    # ----- usuários -----

    def salvar_usuario(self, nome: str, sal: bytes, token_de_verificacao: bytes, parametros_kdf: ParametrosKdf):
        try:
            with closing(self._conectar()) as conexao, conexao:
                conexao.execute(
                    """
                    INSERT INTO usuarios (nome, sal, token_de_verificacao, kdf_n, kdf_r, kdf_p)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (nome, sal, token_de_verificacao, *parametros_kdf),
                )
        except sqlite3.IntegrityError as erro:
            if _e_violacao_de_unicidade(erro):
                raise UsuarioJaExiste("Este usuário já existe.") from None
            raise

    def buscar_usuario(self, nome: str) -> Usuario | None:
        with closing(self._conectar()) as conexao:
            linha = conexao.execute(
                """
                SELECT id, sal, token_de_verificacao, kdf_n, kdf_r, kdf_p
                FROM usuarios WHERE nome = ?
                """,
                (nome,),
            ).fetchone()

        if linha is None:
            return None

        return Usuario(
            id=linha["id"],
            sal=linha["sal"],
            token_de_verificacao=linha["token_de_verificacao"],
            parametros_kdf=ParametrosKdf(linha["kdf_n"], linha["kdf_r"], linha["kdf_p"]),
        )

    # ----- credenciais (TODAS filtram por usuario_id) -----

    def salvar_credencial(self, usuario_id: int, titulo: str, dados_criptografados: bytes):
        try:
            with closing(self._conectar()) as conexao, conexao:
                conexao.execute(
                    "INSERT INTO credenciais (usuario_id, titulo, dados_criptografados) VALUES (?, ?, ?)",
                    (usuario_id, titulo, dados_criptografados),
                )
        except sqlite3.IntegrityError as erro:
            if _e_violacao_de_unicidade(erro):
                raise CredencialJaExiste("Já existe uma credencial com este título.") from None
            raise

    def listar_credenciais(self, usuario_id: int) -> list[sqlite3.Row]:
        """Devolve linhas com (id, titulo). Os dados criptografados ficam de fora."""
        with closing(self._conectar()) as conexao:
            return conexao.execute(
                "SELECT id, titulo FROM credenciais WHERE usuario_id = ? ORDER BY titulo",
                (usuario_id,),
            ).fetchall()

    def buscar_credencial(self, usuario_id: int, credencial_id: int) -> sqlite3.Row | None:
        """Devolve (id, titulo, dados_criptografados) ou None. Só encontra credenciais do dono."""
        with closing(self._conectar()) as conexao:
            return conexao.execute(
                """
                SELECT id, titulo, dados_criptografados
                FROM credenciais WHERE id = ? AND usuario_id = ?
                """,
                (credencial_id, usuario_id),
            ).fetchone()

    def atualizar_credencial(
        self, usuario_id: int, credencial_id: int, titulo: str, dados_criptografados: bytes
    ) -> bool:
        """True se atualizou; False se não existe OU não pertence ao usuário."""
        try:
            with closing(self._conectar()) as conexao, conexao:
                cursor = conexao.execute(
                    """
                    UPDATE credenciais SET titulo = ?, dados_criptografados = ?
                    WHERE id = ? AND usuario_id = ?
                    """,
                    (titulo, dados_criptografados, credencial_id, usuario_id),
                )
                return cursor.rowcount > 0
        except sqlite3.IntegrityError as erro:
            if _e_violacao_de_unicidade(erro):
                raise CredencialJaExiste("Já existe uma credencial com este título.") from None
            raise

    def remover_credencial(self, usuario_id: int, credencial_id: int) -> bool:
        """True se removeu; False se não existe OU não pertence ao usuário."""
        with closing(self._conectar()) as conexao, conexao:
            cursor = conexao.execute(
                "DELETE FROM credenciais WHERE id = ? AND usuario_id = ?",
                (credencial_id, usuario_id),
            )
            return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# API INTERNA PARA A INTERFACE GRÁFICA
# ---------------------------------------------------------------------------

class GerenciadorDeSenhas:
    """
    API interna para a interface gráfica
    - Sessão do usuário (a chave fica só na memória)
    - CRUD de credenciais, sempre restrito ao usuário da sessão
    """

    def __init__(
        self,
        banco: Banco,
        autenticador: Autenticador | None = None,
        comprimento_minimo_senha_mestra: int = COMPRIMENTO_MINIMO_SENHA_MESTRA,
    ):
        self._banco = banco
        self._auth = autenticador or Autenticador()
        self._comprimento_minimo_senha_mestra = comprimento_minimo_senha_mestra
        self._usuario_id: int | None = None
        self._fernet: Fernet | None = None   # a chave, só na memória

    # ----- sessão -----

    @property
    def sessao_ativa(self) -> bool:
        return self._usuario_id is not None and self._fernet is not None

    def cadastrar(self, nome: str, senha: str) -> None:
        """Levanta DadosInvalidos, SenhaMestraFraca ou UsuarioJaExiste."""
        nome = self._normalizar_nome(nome)
        if not nome:
            raise DadosInvalidos("O nome de usuário não pode ser vazio.")

        if len(senha) < self._comprimento_minimo_senha_mestra:
            raise SenhaMestraFraca(
                f"A senha mestra precisa ter pelo menos {self._comprimento_minimo_senha_mestra} caracteres."
            )

        sal, token, parametros_kdf = self._auth.criar_segredos_do_usuario(senha)
        self._banco.salvar_usuario(nome, sal, token, parametros_kdf)

    def entrar(self, nome: str, senha: str) -> None:
        """Levanta CredenciaisInvalidas (usuário inexistente e senha errada são indistinguíveis)."""
        self.sair()  # nunca herdar uma sessão anterior
        nome = self._normalizar_nome(nome)

        usuario = self._banco.buscar_usuario(nome)
        if usuario is None:
            raise CredenciaisInvalidas("Usuário ou senha incorretos.")

        fernet = self._auth.destravar_cofre(
            senha_mestra=senha,
            sal=usuario.sal,
            token_de_verificacao=usuario.token_de_verificacao,
            parametros_kdf=usuario.parametros_kdf,
        )
        if fernet is None:
            raise CredenciaisInvalidas("Usuário ou senha incorretos.")

        # Só atribui depois de tudo dar certo: nada de estado parcial
        self._usuario_id = usuario.id
        self._fernet = fernet

    def sair(self) -> None:
        """Bloqueia o cofre: descarta a chave."""
        self._usuario_id = None
        self._fernet = None

    # ----- CRUD -----

    def adicionar(self, titulo: str, dados: dict) -> None:
        """
        Adiciona uma credencial ao usuário da sessão.
        - titulo: nome da credencial (único por usuário)
        - dados: {'site': str, 'senha': str}
        Levanta CofreBloqueado, DadosInvalidos ou CredencialJaExiste.
        """
        self._exigir_sessao()
        titulo, conteudo = self._validar_credencial(titulo, dados)
        self._banco.salvar_credencial(self._usuario_id, titulo, self._criptografar(conteudo))

    def editar(self, credencial_id: int, titulo: str, dados: dict) -> None:
        """
        Substitui título, site e senha de uma credencial do usuário da sessão.
        Levanta CofreBloqueado, DadosInvalidos, CredencialJaExiste ou CredencialInexistente.
        """
        self._exigir_sessao()
        titulo, conteudo = self._validar_credencial(titulo, dados)
        atualizou = self._banco.atualizar_credencial(
            self._usuario_id, credencial_id, titulo, self._criptografar(conteudo)
        )
        if not atualizou:
            raise CredencialInexistente("Não existe nenhuma credencial com este id.")

    def listar(self) -> list[dict]:
        """
        Devolve só id e título. As senhas continuam criptografadas
        até alguém pedir uma credencial específica com obter().
        """
        self._exigir_sessao()
        registros = self._banco.listar_credenciais(self._usuario_id)
        return [{"id": registro["id"], "titulo": registro["titulo"]} for registro in registros]

    def obter(self, credencial_id: int) -> dict:
        """
        Descriptografa UMA credencial: {'id', 'titulo', 'site', 'senha'}.
        Levanta CredencialInexistente ou CredencialAdulterada.
        """
        self._exigir_sessao()

        registro = self._banco.buscar_credencial(self._usuario_id, credencial_id)
        if registro is None:
            raise CredencialInexistente("Não existe nenhuma credencial com este id.")

        try:
            conteudo = self._descriptografar(registro["dados_criptografados"])
        except InvalidToken:
            raise CredencialAdulterada("Esta credencial está corrompida ou foi alterada.") from None

        if conteudo["titulo"] != registro["titulo"]:
            raise CredencialAdulterada("O título desta credencial foi alterado fora do app.")

        return {
            "id": registro["id"],
            "titulo": conteudo["titulo"],
            "site": conteudo["site"],
            "senha": conteudo["senha"],
        }

    def remover(self, credencial_id: int) -> None:
        """Levanta CredencialInexistente (também quando a credencial é de outro usuário)."""
        self._exigir_sessao()

        if not self._banco.remover_credencial(self._usuario_id, credencial_id):
            raise CredencialInexistente("Não existe nenhuma credencial com este id.")

    # ----- internos -----

    def _exigir_sessao(self):
        if not self.sessao_ativa:
            raise CofreBloqueado("Faça login para acessar o cofre.")

    @staticmethod
    def _validar_credencial(titulo: str, dados: dict) -> tuple[str, dict]:
        """Valida e devolve (titulo_limpo, conteudo_a_criptografar)."""
        titulo = titulo.strip()
        if not titulo:
            raise DadosInvalidos("O título não pode ser vazio.")

        for campo in ("site", "senha"):
            if not isinstance(dados.get(campo), str) or not dados[campo]:
                raise DadosInvalidos(f"O campo '{campo}' é obrigatório.")

        # O título também vai DENTRO do blob criptografado: permite detectar
        # se alguém trocou títulos direto no banco (ver obter).
        return titulo, {"titulo": titulo, "site": dados["site"], "senha": dados["senha"]}

    def _criptografar(self, conteudo: dict) -> bytes:
        """dict -> texto JSON -> bytes -> criptografado."""
        return self._fernet.encrypt(json.dumps(conteudo).encode("utf-8"))

    def _descriptografar(self, dados_criptografados: bytes) -> dict:
        """criptografado -> bytes -> texto JSON -> dict. Levanta InvalidToken se adulterado."""
        texto_json = self._fernet.decrypt(dados_criptografados).decode("utf-8")
        return json.loads(texto_json)

    @staticmethod
    def _normalizar_nome(nome: str) -> str:
        """'  Ana ' e 'ana' são o mesmo usuário."""
        return nome.strip().casefold()
