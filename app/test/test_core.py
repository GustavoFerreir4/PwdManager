"""
test_core.py — suíte de testes do core.py.

Rodar:  pytest
(a configuração de cobertura com branches está no pytest.ini)
"""

import os
import sqlite3
import stat
from contextlib import closing

import pytest
from cryptography.fernet import Fernet

import core
from core import (
    Autenticador,
    Banco,
    CofreBloqueado,
    CredencialAdulterada,
    CredencialInexistente,
    CredencialJaExiste,
    CredenciaisInvalidas,
    DadosInvalidos,
    ErroDoCofre,
    EsquemaIncompativel,
    GerenciadorDeSenhas,
    ParametrosKdf,
    SenhaMestraFraca,
    UsuarioJaExiste,
)

# KDF barato para os testes ficarem rápidos (n=2**4 em vez dos 2**17 de produção)
PARAMETROS_RAPIDOS = ParametrosKdf(n=2**4, r=8, p=1)

SAL = b"0123456789abcdef"
OUTRO_SAL = b"fedcba9876543210"

SENHA_MESTRA = "senha-mestra-da-ana"
SENHA_MESTRA_DO_BOB = "senha-mestra-do-bob!"
DADOS_GMAIL = {"site": "gmail.com", "senha": "S3nh@DoGmail"}
DADOS_GITHUB = {"site": "github.com", "senha": "gh-p4ss-xyz"}


# ---------------------------------------------------------------------------
# FIXTURES E AJUDANTES
# ---------------------------------------------------------------------------

@pytest.fixture
def autenticador():
    return Autenticador(PARAMETROS_RAPIDOS)


@pytest.fixture
def banco(tmp_path):
    return Banco(str(tmp_path / "teste.db"))


@pytest.fixture
def gerenciador(banco, autenticador):
    """Gerenciador SEM login."""
    return GerenciadorDeSenhas(banco, autenticador)


@pytest.fixture
def ana(gerenciador):
    """Gerenciador com a Ana logada."""
    gerenciador.cadastrar("ana", SENHA_MESTRA)
    gerenciador.entrar("ana", SENHA_MESTRA)
    return gerenciador


@pytest.fixture
def bob(banco, autenticador):
    """Outro usuário, no MESMO banco da Ana (para testar isolamento)."""
    outro = GerenciadorDeSenhas(banco, autenticador)
    outro.cadastrar("bob", SENHA_MESTRA_DO_BOB)
    outro.entrar("bob", SENHA_MESTRA_DO_BOB)
    return outro


def executar_sql(banco, comando, parametros=()):
    """Mexe direto no banco, como faria alguém de fora do app."""
    with closing(banco._conectar()) as conexao, conexao:
        return conexao.execute(comando, parametros).fetchall()


def criar_usuario(banco, nome="ana"):
    banco.salvar_usuario(nome, SAL, b"token", PARAMETROS_RAPIDOS)
    return banco.buscar_usuario(nome).id


# ---------------------------------------------------------------------------
# AUTENTICADOR
# ---------------------------------------------------------------------------

def test_parametros_padrao_do_kdf():
    assert ParametrosKdf() == (2**17, 8, 1)


def test_custo_padrao_do_kdf_e_aceito_pelo_openssl():
    # Teste de fumaça (~0,4 s): garante que 2**17 funciona de verdade nesta máquina
    chave = Autenticador().gerar_chave("senha", SAL, ParametrosKdf())
    Fernet(chave)  # não deve levantar


def test_gerar_chave_e_deterministica(autenticador):
    chave_1 = autenticador.gerar_chave("abc", SAL, PARAMETROS_RAPIDOS)
    chave_2 = autenticador.gerar_chave("abc", SAL, PARAMETROS_RAPIDOS)
    assert chave_1 == chave_2
    Fernet(chave_1)  # é uma chave Fernet válida


@pytest.mark.parametrize("senha, sal", [("abd", SAL), ("abc", OUTRO_SAL)])
def test_gerar_chave_muda_com_senha_ou_sal(autenticador, senha, sal):
    original = autenticador.gerar_chave("abc", SAL, PARAMETROS_RAPIDOS)
    assert autenticador.gerar_chave(senha, sal, PARAMETROS_RAPIDOS) != original


def test_criar_segredos_do_usuario(autenticador):
    sal, token, parametros = autenticador.criar_segredos_do_usuario(SENHA_MESTRA)

    assert len(sal) == 16
    assert parametros == PARAMETROS_RAPIDOS
    assert token != core.TEXTO_DE_VERIFICACAO

    chave = autenticador.gerar_chave(SENHA_MESTRA, sal, parametros)
    assert Fernet(chave).decrypt(token) == core.TEXTO_DE_VERIFICACAO


def test_cada_cadastro_gera_sal_diferente(autenticador):
    sal_1, _, _ = autenticador.criar_segredos_do_usuario(SENHA_MESTRA)
    sal_2, _, _ = autenticador.criar_segredos_do_usuario(SENHA_MESTRA)
    assert sal_1 != sal_2


def test_destravar_cofre_com_senha_certa(autenticador):
    sal, token, parametros = autenticador.criar_segredos_do_usuario(SENHA_MESTRA)

    fernet = autenticador.destravar_cofre(SENHA_MESTRA, sal, token, parametros)

    assert isinstance(fernet, Fernet)
    assert fernet.decrypt(token) == core.TEXTO_DE_VERIFICACAO


def test_destravar_cofre_com_senha_errada_devolve_none(autenticador):
    sal, token, parametros = autenticador.criar_segredos_do_usuario(SENHA_MESTRA)
    assert autenticador.destravar_cofre("senha-errada", sal, token, parametros) is None


def test_destravar_usa_os_parametros_salvos_e_nao_os_do_autenticador():
    antigo = Autenticador(ParametrosKdf(n=2**4, r=8, p=1))
    novo = Autenticador(ParametrosKdf(n=2**5, r=8, p=1))
    sal, token, parametros = antigo.criar_segredos_do_usuario(SENHA_MESTRA)

    assert novo.destravar_cofre(SENHA_MESTRA, sal, token, parametros) is not None


# ---------------------------------------------------------------------------
# BANCO — esquema
# ---------------------------------------------------------------------------

def test_banco_novo_registra_a_versao_do_esquema(banco):
    versao = executar_sql(banco, "PRAGMA user_version")[0][0]
    assert versao == core.VERSAO_DO_ESQUEMA


def test_reabrir_banco_existente_preserva_os_dados(tmp_path):
    arquivo = str(tmp_path / "reaberto.db")
    Banco(arquivo).salvar_usuario("ana", SAL, b"token", PARAMETROS_RAPIDOS)

    assert Banco(arquivo).buscar_usuario("ana") is not None


def test_banco_com_esquema_antigo_levanta_erro(tmp_path):
    arquivo = str(tmp_path / "antigo.db")
    with closing(sqlite3.connect(arquivo)) as conexao, conexao:
        conexao.execute("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, nome TEXT)")

    with pytest.raises(EsquemaIncompativel):
        Banco(arquivo)


@pytest.mark.skipif(os.name == "nt", reason="chmod não restringe acesso no Windows")
def test_arquivo_do_banco_so_o_dono_acessa(banco):
    assert stat.S_IMODE(os.stat(banco.arquivo).st_mode) == 0o600


# ---------------------------------------------------------------------------
# BANCO — usuários
# ---------------------------------------------------------------------------

def test_salvar_e_buscar_usuario(banco):
    banco.salvar_usuario("ana", SAL, b"token", PARAMETROS_RAPIDOS)

    usuario = banco.buscar_usuario("ana")

    assert isinstance(usuario.id, int)
    assert usuario.sal == SAL
    assert usuario.token_de_verificacao == b"token"
    assert usuario.parametros_kdf == PARAMETROS_RAPIDOS


def test_buscar_usuario_inexistente_devolve_none(banco):
    assert banco.buscar_usuario("ninguem") is None


def test_salvar_usuario_duplicado_levanta_usuario_ja_existe(banco):
    banco.salvar_usuario("ana", SAL, b"token", PARAMETROS_RAPIDOS)

    with pytest.raises(UsuarioJaExiste):
        banco.salvar_usuario("ana", OUTRO_SAL, b"outro", PARAMETROS_RAPIDOS)


def test_erro_de_integridade_que_nao_e_unicidade_nao_e_disfarcado(banco):
    # nome=None viola NOT NULL, e isso NÃO deve virar "usuário já existe"
    with pytest.raises(sqlite3.IntegrityError):
        banco.salvar_usuario(None, SAL, b"token", PARAMETROS_RAPIDOS)


# ---------------------------------------------------------------------------
# BANCO — credenciais
# ---------------------------------------------------------------------------

def test_salvar_e_listar_credenciais_ordenadas_por_titulo(banco):
    usuario_id = criar_usuario(banco)
    banco.salvar_credencial(usuario_id, "Zeta", b"blob-1")
    banco.salvar_credencial(usuario_id, "Alfa", b"blob-2")

    linhas = banco.listar_credenciais(usuario_id)

    assert [linha["titulo"] for linha in linhas] == ["Alfa", "Zeta"]
    assert linhas[0].keys() == ["id", "titulo"]  # o blob criptografado nem sai do banco


def test_titulo_duplicado_para_o_mesmo_usuario(banco):
    usuario_id = criar_usuario(banco)
    banco.salvar_credencial(usuario_id, "Gmail", b"blob")

    with pytest.raises(CredencialJaExiste):
        banco.salvar_credencial(usuario_id, "Gmail", b"outro-blob")


def test_mesmo_titulo_para_usuarios_diferentes_e_permitido(banco):
    ana_id = criar_usuario(banco, "ana")
    bob_id = criar_usuario(banco, "bob")

    banco.salvar_credencial(ana_id, "Gmail", b"blob-ana")
    banco.salvar_credencial(bob_id, "Gmail", b"blob-bob")

    assert len(banco.listar_credenciais(ana_id)) == 1
    assert len(banco.listar_credenciais(bob_id)) == 1


def test_credencial_de_usuario_inexistente_nao_vira_titulo_duplicado(banco):
    # Violação de chave estrangeira: também é IntegrityError, mas não de unicidade
    with pytest.raises(sqlite3.IntegrityError):
        banco.salvar_credencial(999, "Gmail", b"blob")


def test_buscar_credencial_so_encontra_do_dono(banco):
    ana_id = criar_usuario(banco, "ana")
    bob_id = criar_usuario(banco, "bob")
    banco.salvar_credencial(ana_id, "Gmail", b"blob")
    credencial_id = banco.listar_credenciais(ana_id)[0]["id"]

    achada = banco.buscar_credencial(ana_id, credencial_id)
    assert achada["titulo"] == "Gmail"
    assert achada["dados_criptografados"] == b"blob"

    assert banco.buscar_credencial(bob_id, credencial_id) is None
    assert banco.buscar_credencial(ana_id, 999) is None


def test_remover_credencial_so_remove_do_dono(banco):
    ana_id = criar_usuario(banco, "ana")
    bob_id = criar_usuario(banco, "bob")
    banco.salvar_credencial(ana_id, "Gmail", b"blob")
    credencial_id = banco.listar_credenciais(ana_id)[0]["id"]

    assert banco.remover_credencial(bob_id, credencial_id) is False
    assert len(banco.listar_credenciais(ana_id)) == 1  # continua lá

    assert banco.remover_credencial(ana_id, credencial_id) is True
    assert banco.listar_credenciais(ana_id) == []

    assert banco.remover_credencial(ana_id, credencial_id) is False  # já não existe


def test_remover_usuario_apaga_as_credenciais_em_cascata(banco):
    usuario_id = criar_usuario(banco)
    banco.salvar_credencial(usuario_id, "Gmail", b"blob")

    executar_sql(banco, "DELETE FROM usuarios WHERE id = ?", (usuario_id,))

    assert executar_sql(banco, "SELECT * FROM credenciais") == []


# ---------------------------------------------------------------------------
# GERENCIADOR — cadastro
# ---------------------------------------------------------------------------

def test_cadastrar_grava_no_banco_injetado(gerenciador, banco):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    assert banco.buscar_usuario("ana") is not None


def test_cadastrar_guarda_os_parametros_do_kdf_do_usuario(gerenciador, banco):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    assert banco.buscar_usuario("ana").parametros_kdf == PARAMETROS_RAPIDOS


def test_cadastrar_rejeita_senha_mestra_fraca(gerenciador, banco):
    with pytest.raises(SenhaMestraFraca):
        gerenciador.cadastrar("ana", "curta")

    assert banco.buscar_usuario("ana") is None


def test_comprimento_minimo_da_senha_mestra_e_configuravel(banco, autenticador):
    exigente = GerenciadorDeSenhas(banco, autenticador, comprimento_minimo_senha_mestra=30)

    with pytest.raises(SenhaMestraFraca):
        exigente.cadastrar("ana", SENHA_MESTRA)  # 19 caracteres


def test_senha_mestra_no_limite_do_comprimento_minimo(gerenciador):
    # 12 caracteres (o mínimo) passa; 11 não
    gerenciador.cadastrar("ana", "a" * core.COMPRIMENTO_MINIMO_SENHA_MESTRA)

    with pytest.raises(SenhaMestraFraca):
        gerenciador.cadastrar("bob", "a" * (core.COMPRIMENTO_MINIMO_SENHA_MESTRA - 1))


@pytest.mark.parametrize("nome", ["", "   "])
def test_cadastrar_rejeita_nome_vazio(gerenciador, nome):
    with pytest.raises(DadosInvalidos):
        gerenciador.cadastrar(nome, SENHA_MESTRA)


def test_cadastrar_nome_repetido_mesmo_com_caixa_e_espacos_diferentes(gerenciador):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    with pytest.raises(UsuarioJaExiste):
        gerenciador.cadastrar("  ANA ", SENHA_MESTRA)


def test_todos_os_erros_herdam_de_erro_do_cofre():
    for erro in (UsuarioJaExiste, CredenciaisInvalidas, CofreBloqueado, CredencialAdulterada):
        assert issubclass(erro, ErroDoCofre)


# ---------------------------------------------------------------------------
# GERENCIADOR — sessão
# ---------------------------------------------------------------------------

def test_gerenciador_novo_nao_tem_sessao(gerenciador):
    assert gerenciador.sessao_ativa is False


def test_gerenciador_usa_autenticador_padrao_se_nao_receber_um(banco):
    assert GerenciadorDeSenhas(banco).sessao_ativa is False


def test_entrar_com_senha_certa_abre_a_sessao(gerenciador):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    gerenciador.entrar("ana", SENHA_MESTRA)

    assert gerenciador.sessao_ativa is True


def test_entrar_normaliza_o_nome(gerenciador):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    gerenciador.entrar("  ANA ", SENHA_MESTRA)

    assert gerenciador.sessao_ativa is True


def test_entrar_com_senha_errada(gerenciador):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    with pytest.raises(CredenciaisInvalidas):
        gerenciador.entrar("ana", "senha-errada-123")

    assert gerenciador.sessao_ativa is False


def test_entrar_com_usuario_inexistente(gerenciador):
    with pytest.raises(CredenciaisInvalidas):
        gerenciador.entrar("ninguem", SENHA_MESTRA)

    assert gerenciador.sessao_ativa is False


def test_usuario_inexistente_e_senha_errada_dao_a_mesma_mensagem(gerenciador):
    gerenciador.cadastrar("ana", SENHA_MESTRA)

    with pytest.raises(CredenciaisInvalidas) as senha_errada:
        gerenciador.entrar("ana", "senha-errada-123")
    with pytest.raises(CredenciaisInvalidas) as sem_usuario:
        gerenciador.entrar("ninguem", "senha-errada-123")

    assert str(senha_errada.value) == str(sem_usuario.value)


def test_login_que_falha_encerra_a_sessao_anterior(ana):
    assert ana.sessao_ativa is True

    with pytest.raises(CredenciaisInvalidas):
        ana.entrar("ana", "senha-errada-123")

    assert ana.sessao_ativa is False
    with pytest.raises(CofreBloqueado):
        ana.listar()


def test_login_continua_funcionando_depois_que_o_custo_padrao_do_kdf_muda(banco):
    antigo = GerenciadorDeSenhas(banco, Autenticador(ParametrosKdf(n=2**4, r=8, p=1)))
    antigo.cadastrar("ana", SENHA_MESTRA)

    mais_caro = GerenciadorDeSenhas(banco, Autenticador(ParametrosKdf(n=2**5, r=8, p=1)))
    mais_caro.entrar("ana", SENHA_MESTRA)

    assert mais_caro.sessao_ativa is True


def test_login_usa_o_custo_salvo_do_usuario_e_nao_o_do_autenticador(banco):
    # Usuário criado com custo MAIOR que o do autenticador que fará o login
    caro = GerenciadorDeSenhas(banco, Autenticador(ParametrosKdf(n=2**5, r=8, p=1)))
    caro.cadastrar("ana", SENHA_MESTRA)

    barato = GerenciadorDeSenhas(banco, Autenticador(ParametrosKdf(n=2**4, r=8, p=1)))
    barato.entrar("ana", SENHA_MESTRA)

    assert barato.sessao_ativa is True


def test_sair_bloqueia_o_cofre(ana):
    ana.sair()

    assert ana.sessao_ativa is False
    with pytest.raises(CofreBloqueado):
        ana.listar()


OPERACOES_DO_CRUD = [
    lambda g: g.adicionar("Gmail", DADOS_GMAIL),
    lambda g: g.listar(),
    lambda g: g.obter(1),
    lambda g: g.remover(1),
]


@pytest.mark.parametrize("operacao", OPERACOES_DO_CRUD)
def test_crud_exige_sessao_antes_do_login(gerenciador, operacao):
    with pytest.raises(CofreBloqueado):
        operacao(gerenciador)


@pytest.mark.parametrize("operacao", OPERACOES_DO_CRUD)
def test_crud_exige_sessao_depois_de_sair(ana, operacao):
    ana.sair()

    with pytest.raises(CofreBloqueado):
        operacao(ana)


def test_senha_mestra_e_senhas_salvas_nunca_aparecem_no_arquivo_do_banco(ana, banco):
    ana.adicionar("Gmail", DADOS_GMAIL)

    with open(banco.arquivo, "rb") as arquivo:
        bytes_do_banco = arquivo.read()

    assert SENHA_MESTRA.encode() not in bytes_do_banco
    assert DADOS_GMAIL["senha"].encode() not in bytes_do_banco
    assert DADOS_GMAIL["site"].encode() not in bytes_do_banco


# ---------------------------------------------------------------------------
# GERENCIADOR — CRUD
# ---------------------------------------------------------------------------

def test_listar_sem_credenciais(ana):
    assert ana.listar() == []


def test_adicionar_listar_e_obter(ana):
    ana.adicionar("Gmail", DADOS_GMAIL)

    lista = ana.listar()
    assert len(lista) == 1
    assert lista[0]["titulo"] == "Gmail"

    credencial = ana.obter(lista[0]["id"])
    assert credencial == {
        "id": lista[0]["id"],
        "titulo": "Gmail",
        "site": "gmail.com",
        "senha": "S3nh@DoGmail",
    }


def test_listar_nao_expoe_senhas_nem_sites(ana):
    ana.adicionar("Gmail", DADOS_GMAIL)

    assert set(ana.listar()[0].keys()) == {"id", "titulo"}


def test_listar_vem_ordenado_por_titulo(ana):
    ana.adicionar("Zeta", DADOS_GMAIL)
    ana.adicionar("Alfa", DADOS_GITHUB)

    assert [item["titulo"] for item in ana.listar()] == ["Alfa", "Zeta"]


def test_senha_curta_de_credencial_e_aceita(ana):
    # Quem manda no formato da senha de um SITE é o site (PINs existem), não o cofre
    ana.adicionar("Banco", {"site": "banco.com", "senha": "1234"})

    assert ana.obter(ana.listar()[0]["id"])["senha"] == "1234"


def test_caracteres_nao_ascii_sobrevivem_ao_ciclo(ana):
    ana.adicionar("Cartão", {"site": "açaí.com.br", "senha": "çãõ-Ünï©ödé"})

    credencial = ana.obter(ana.listar()[0]["id"])

    assert credencial["titulo"] == "Cartão"
    assert credencial["senha"] == "çãõ-Ünï©ödé"


@pytest.mark.parametrize(
    "titulo, dados",
    [
        ("", DADOS_GMAIL),
        ("   ", DADOS_GMAIL),
        ("Gmail", {"senha": "abc"}),                    # falta o site
        ("Gmail", {"site": "gmail.com"}),               # falta a senha
        ("Gmail", {"site": "", "senha": "abc"}),        # site vazio
        ("Gmail", {"site": "gmail.com", "senha": ""}),  # senha vazia
        ("Gmail", {"site": "gmail.com", "senha": 1234}),  # senha não é texto
    ],
)
def test_adicionar_rejeita_dados_invalidos(ana, titulo, dados):
    with pytest.raises(DadosInvalidos):
        ana.adicionar(titulo, dados)

    assert ana.listar() == []


def test_adicionar_titulo_duplicado(ana):
    ana.adicionar("Gmail", DADOS_GMAIL)

    with pytest.raises(CredencialJaExiste):
        ana.adicionar("Gmail", DADOS_GITHUB)


def test_adicionar_titulo_duplicado_mesmo_com_espacos_nas_pontas(ana):
    ana.adicionar("Gmail", DADOS_GMAIL)

    with pytest.raises(CredencialJaExiste):
        ana.adicionar("  Gmail  ", DADOS_GITHUB)


def test_dois_usuarios_podem_ter_credenciais_com_o_mesmo_titulo(ana, bob):
    ana.adicionar("Gmail", DADOS_GMAIL)
    bob.adicionar("Gmail", DADOS_GITHUB)  # não pode vazar que a Ana já usou o título

    assert ana.obter(ana.listar()[0]["id"])["senha"] == DADOS_GMAIL["senha"]
    assert bob.obter(bob.listar()[0]["id"])["senha"] == DADOS_GITHUB["senha"]


def test_obter_credencial_inexistente(ana):
    with pytest.raises(CredencialInexistente):
        ana.obter(999)


def test_remover_credencial(ana):
    ana.adicionar("Gmail", DADOS_GMAIL)
    credencial_id = ana.listar()[0]["id"]

    ana.remover(credencial_id)

    assert ana.listar() == []


def test_remover_credencial_inexistente(ana):
    with pytest.raises(CredencialInexistente):
        ana.remover(999)


# ---------------------------------------------------------------------------
# GERENCIADOR — isolamento entre usuários
# ---------------------------------------------------------------------------

def test_um_usuario_nao_ve_as_credenciais_do_outro(ana, bob):
    ana.adicionar("Gmail", DADOS_GMAIL)

    assert bob.listar() == []


def test_um_usuario_nao_consegue_obter_credencial_de_outro(ana, bob):
    ana.adicionar("Gmail", DADOS_GMAIL)
    id_da_ana = ana.listar()[0]["id"]

    with pytest.raises(CredencialInexistente):
        bob.obter(id_da_ana)


def test_um_usuario_nao_consegue_remover_credencial_de_outro(ana, bob):
    # Regressão: no código antigo o Bob conseguia apagar a credencial da Ana pelo id
    ana.adicionar("Gmail", DADOS_GMAIL)
    id_da_ana = ana.listar()[0]["id"]

    with pytest.raises(CredencialInexistente):
        bob.remover(id_da_ana)

    assert len(ana.listar()) == 1


# ---------------------------------------------------------------------------
# GERENCIADOR — adulteração do banco
# ---------------------------------------------------------------------------

def test_blob_corrompido_levanta_credencial_adulterada(ana, banco):
    ana.adicionar("Gmail", DADOS_GMAIL)
    executar_sql(banco, "UPDATE credenciais SET dados_criptografados = ?", (b"lixo",))

    with pytest.raises(CredencialAdulterada):
        ana.obter(ana.listar()[0]["id"])


def test_blob_de_outra_chave_levanta_credencial_adulterada(ana, bob, banco):
    # Alguém copia o blob do Bob para o registro da Ana: a chave não confere
    bob.adicionar("Gmail", DADOS_GITHUB)
    ana.adicionar("Gmail", DADOS_GMAIL)
    id_da_ana = banco.buscar_usuario("ana").id
    id_do_bob = banco.buscar_usuario("bob").id
    blob_do_bob = executar_sql(
        banco, "SELECT dados_criptografados FROM credenciais WHERE usuario_id = ?", (id_do_bob,)
    )[0][0]
    executar_sql(
        banco, "UPDATE credenciais SET dados_criptografados = ? WHERE usuario_id = ?", (blob_do_bob, id_da_ana)
    )

    with pytest.raises(CredencialAdulterada):
        ana.obter(ana.listar()[0]["id"])


def test_titulo_trocado_no_banco_levanta_credencial_adulterada(ana, banco):
    ana.adicionar("Gmail", DADOS_GMAIL)
    executar_sql(banco, "UPDATE credenciais SET titulo = 'Banco'")

    with pytest.raises(CredencialAdulterada):
        ana.obter(ana.listar()[0]["id"])
