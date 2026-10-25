"""
gui.py — interface gráfica do gerenciador de senhas, integrada ao core.py.

Baseado em GUI_prototipo.py (mesmos nomes de classes, widgets e posições).
A GUI só conversa com o GerenciadorDeSenhas; erros chegam como ErroDoCofre.

Requer Python 3.10+ e:  pip install cryptography
Execute com:            python gui.py
"""

import os
import tkinter as tk
from contextlib import contextmanager
from tkinter import messagebox
from tkinter import ttk

from core import Banco, ErroDoCofre, EsquemaIncompativel, GerenciadorDeSenhas

# O banco fica ao lado deste arquivo, não na pasta de onde o programa foi chamado.
CAMINHO_DO_BANCO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")


# ---------------------------------------------------------------------------
# TEMA E COMPONENTES COMUNS
# ---------------------------------------------------------------------------

THEME_BG = "#303030"
THEME_FG = "#1a1a1a"
THEME_ACCENT = "#2a7de1"
THEME_ACCENT_FG = "#ffffff"
THEME_FIELD_BG = "#ffffff"
THEME_FONT = ("Helvetica", 10)


def apply_theme(root):
    """Apply the project theme as defaults; per-widget options override these."""
    root.configure(bg=THEME_BG)
    root.option_add("*background", THEME_BG)
    root.option_add("*foreground", THEME_FG)
    root.option_add("*font", THEME_FONT)
    root.option_add("*Entry.background", THEME_FIELD_BG)
    root.option_add("*Text.background", THEME_FIELD_BG)
    root.option_add("*Listbox.background", THEME_FIELD_BG)
    root.option_add("*Button.background", THEME_ACCENT)
    root.option_add("*Button.foreground", THEME_ACCENT_FG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=THEME_BG, foreground=THEME_FG, fieldbackground=THEME_FIELD_BG, font=THEME_FONT)


@contextmanager
def ocupado(janela):
    """Cursor de espera durante operações lentas (o Scrypt leva alguns instantes)."""
    janela.config(cursor="watch")
    janela.update_idletasks()
    try:
        yield
    finally:
        janela.config(cursor="")


def tornar_popup(janela, master, largura, altura, ao_fechar):
    """Centraliza sobre a janela-mãe, bloqueia a mãe (foco) e liga as formas de fechar."""
    master.update_idletasks()
    x = master.winfo_rootx() + (master.winfo_width() - largura) // 2
    y = master.winfo_rooty() + (master.winfo_height() - altura) // 2
    janela.geometry(f"{largura}x{altura}+{max(x, 0)}+{max(y, 0)}")
    janela.resizable(False, False)
    janela.transient(master)                          # fica sempre acima da janela-mãe
    janela.protocol("WM_DELETE_WINDOW", ao_fechar)    # o "X" da janela
    janela.bind("<Escape>", lambda _e: ao_fechar())   # Esc
    janela.wait_visibility()                          # grab_set exige a janela visível
    janela.grab_set()                                 # bloqueia cliques na janela-mãe
    janela.focus_force()


class ScrollableFrame(tk.Frame):
    """A frame that scrolls. Put your widgets in `.body`, not in this."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self._canvas = tk.Canvas(self, highlightthickness=0)
        self._bar = tk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._bar.set)
        self._bar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self.body = tk.Frame(self._canvas)
        self._window = self._canvas.create_window((0, 0), window=self.body, anchor="nw")
        # The scroll region follows whatever size the body is given.
        self.body.bind("<Configure>", self._on_body)
        # Roda do mouse (Windows/macOS: <MouseWheel>; Linux: Button-4/5)
        for evento in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(evento, self._on_roda, add="+")

    def _on_body(self, _event=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_roda(self, evento):
        if not self.winfo_exists():
            return
        alvo = self.winfo_containing(evento.x_root, evento.y_root)
        if alvo is None or not str(alvo).startswith(str(self)):
            return  # o mouse não está sobre esta lista (ex.: está sobre um pop-up)
        if evento.num == 4:
            passos = -1
        elif evento.num == 5:
            passos = 1
        else:
            passos = -1 if evento.delta > 0 else 1
        self._canvas.yview_scroll(passos, "units")


# ---------------------------------------------------------------------------
# POP-UP: CRIAR / EDITAR CREDENCIAL
# ---------------------------------------------------------------------------

class PasswordManagerAppCriarCredencial:
    """
    Pop-up modal (em foco) para criar ou editar uma credencial.
    - ao_salvar(titulo, dados): chamado ao confirmar; pode levantar ErroDoCofre
      (o erro é mostrado aqui e o pop-up continua aberto para o usuário corrigir).
    - credencial: dict de obter(); se vier, o pop-up funciona como edição.
    """

    LARGURA = 480
    ALTURA = 290

    def __init__(self, master, ao_salvar, credencial=None):
        root = tk.Toplevel(master)
        self.root = root
        self._ao_salvar = ao_salvar
        editando = credencial is not None
        root.title("Password Manager App - " + ("Editar" if editando else "Criar") + " credencial")
        apply_theme(root)

        self.cb_mostrar_senha_var = tk.IntVar()

        self.f_criar_credencial = tk.Frame(root, relief="groove", bd=2)
        self.f_criar_credencial.place(x=0, y=0, width=self.LARGURA, height=self.ALTURA)

        self.l_nome_da_credencial = tk.Label(self.f_criar_credencial, text="Nome da Credencial:", fg="#ffffff")
        self.l_nome_da_credencial.place(x=40, y=20, width=130, height=30)

        self.l_dominio_da_credencial = tk.Label(self.f_criar_credencial, text="Dominio:", fg="#ffffff")
        self.l_dominio_da_credencial.place(x=40, y=100, width=60, height=30)

        self.l_senha = tk.Label(self.f_criar_credencial, text="Senha:", fg="#ffffff")
        self.l_senha.place(x=40, y=180, width=60, height=30)

        self.e_nome_da_credencial = tk.Entry(self.f_criar_credencial)
        self.e_nome_da_credencial.place(x=210, y=20, width=220, height=30)

        self.e_dominio_da_credencial = tk.Entry(self.f_criar_credencial)
        self.e_dominio_da_credencial.place(x=210, y=100, width=220, height=30)

        self.e_senha = tk.Entry(self.f_criar_credencial, show="*")
        self.e_senha.place(x=210, y=180, width=220, height=30)

        self.cb_mostrar_senha = tk.Checkbutton(self.f_criar_credencial, text="mostrar", variable=self.cb_mostrar_senha_var, command=self.on_cb_mostrar_senha, fg="#ffffff", font=("Helvetica", 9))
        self.cb_mostrar_senha.place(x=205, y=214, width=77, height=22)

        self.b_confirmar_criacao_senha = tk.Button(self.f_criar_credencial, text="Confirmar", command=self.on_b_confirmar_criacao_senha, bg="#62964f")
        self.b_confirmar_criacao_senha.place(x=360, y=250, width=70, height=20)

        self.b_cancelar_cricao_senha = tk.Button(self.f_criar_credencial, text="Cancelar", command=self.on_b_cancelar_cricao_senha, bg="#e02929")
        self.b_cancelar_cricao_senha.place(x=260, y=250, width=70, height=20)

        if editando:
            self.e_nome_da_credencial.insert(0, credencial["titulo"])
            self.e_dominio_da_credencial.insert(0, credencial["site"])
            self.e_senha.insert(0, credencial["senha"])

        root.bind("<Return>", lambda _e: self.on_b_confirmar_criacao_senha())
        tornar_popup(root, master, self.LARGURA, self.ALTURA, self.fechar)
        self.e_nome_da_credencial.focus_set()

    def fechar(self):
        self.root.grab_release()
        self.root.destroy()

    def on_cb_mostrar_senha(self):
        self.e_senha.configure(show="" if self.cb_mostrar_senha_var.get() else "*")

    def on_b_confirmar_criacao_senha(self):
        titulo = self.e_nome_da_credencial.get()
        dados = {
            "site": self.e_dominio_da_credencial.get().strip(),
            "senha": self.e_senha.get(),
        }
        try:
            self._ao_salvar(titulo, dados)
        except ErroDoCofre as erro:
            messagebox.showerror("Não foi possível salvar", str(erro), parent=self.root)
            return
        self.fechar()

    def on_b_cancelar_cricao_senha(self):
        self.fechar()


# ---------------------------------------------------------------------------
# POP-UP: EXCLUIR CREDENCIAL
# ---------------------------------------------------------------------------

class PasswordManagerAppExcluirCredencial:
    """Pop-up modal de confirmação. ao_confirmar() é chamado ao clicar em Excluir."""

    def __init__(self, master, ao_confirmar):
        root = tk.Toplevel(master)
        self.root = root
        self._ao_confirmar = ao_confirmar
        root.title("Password Manager App - Excluir Credencial")
        apply_theme(root)

        self.label1 = tk.Label(root, text="Tem certeza que deseja excluir essa credencial? (irreversível)", fg="#ffffff", font=("Helvetica", 15), wraplength=320, justify="center")
        self.label1.place(x=40, y=40, width=320, height=100)

        self.b_confirma_excluir = tk.Button(root, text="Excluir", command=self.on_b_confirma_excluir, fg="#ffffff", bg="#921717")
        self.b_confirma_excluir.place(x=88, y=154, width=96, height=32)

        self.button2 = tk.Button(root, text="Cancelar", command=self.on_button2, fg="#ffffff", bg="#46883f")
        self.button2.place(x=209, y=154, width=96, height=32)

        tornar_popup(root, master, 400, 250, self.fechar)
        self.button2.focus_set()  # o foco inicial fica no botão seguro

    def fechar(self):
        self.root.grab_release()
        self.root.destroy()

    def on_b_confirma_excluir(self):
        try:
            self._ao_confirmar()
        except ErroDoCofre as erro:
            messagebox.showerror("Não foi possível excluir", str(erro), parent=self.root)
        self.fechar()

    def on_button2(self):
        self.fechar()


# ---------------------------------------------------------------------------
# JANELA: CREDENCIAIS
# ---------------------------------------------------------------------------

class PasswordManagerAppCredenciais:
    CARD_X = 154
    CARD_Y = 22
    CARD_LARGURA = 484
    CARD_ALTURA = 176
    CARD_ESPACO = 20

    def __init__(self, master, gerenciador, ao_sair):
        root = tk.Toplevel(master)
        self.root = root
        self.gerenciador = gerenciador
        self._ao_sair = ao_sair
        self._fechada = False
        root.title("Password Manager App - Credenciais")
        root.geometry("800x600")
        apply_theme(root)
        root.protocol("WM_DELETE_WINDOW", self.on_b_sair)  # fechar no "X" também bloqueia o cofre

        self._variaveis_ocultar = []  # o Tk não guarda referência das IntVar: nós guardamos

        # Barra superior
        self.f_topo = tk.Frame(root, relief="groove", bd=2)
        self.f_topo.place(x=0, y=0, width=800, height=50)

        self.b_adicionar_credencial = tk.Button(self.f_topo, text="ADICIONAR CREDENCIAL", command=self.on_b_adicionar_credencial, bg="#62964f", fg="#ffffff", font=("Helvetica", 10, "bold"))
        self.b_adicionar_credencial.place(x=12, y=8, width=210, height=30)

        self.b_sair = tk.Button(self.f_topo, text="SAIR", command=self.on_b_sair, bg="#e02929", fg="#ffffff", font=("Helvetica", 10, "bold"))
        self.b_sair.place(x=682, y=8, width=100, height=30)

        self.sf_lista_de_credenciais = ScrollableFrame(root)
        self.sf_lista_de_credenciais.place(x=0, y=50, width=800, height=550)

        self.carregar_credenciais()

    # ----- lista -----

    def carregar_credenciais(self):
        """Redesenha a lista a partir do core (uma credencial por 'card')."""
        corpo = self.sf_lista_de_credenciais.body
        for filho in corpo.winfo_children():
            filho.destroy()
        self._variaveis_ocultar = []

        try:
            itens = self.gerenciador.listar()
        except ErroDoCofre as erro:  # ex.: CofreBloqueado
            messagebox.showerror("Cofre bloqueado", str(erro), parent=self.root)
            self.on_b_sair()
            return

        if not itens:
            self.l_lista_vazia = tk.Label(
                corpo,
                text="Nenhuma credencial cadastrada.\nClique em ADICIONAR CREDENCIAL para começar.",
                fg="#ffffff",
                font=("Helvetica", 15),
            )
            self.l_lista_vazia.place(x=0, y=200, width=784, height=80)

        passo = self.CARD_ALTURA + self.CARD_ESPACO
        for indice, item in enumerate(itens):
            self._criar_card(corpo, self.CARD_Y + indice * passo, item["id"], item["titulo"])

        altura_total = self.CARD_Y + len(itens) * passo
        corpo.configure(width=784, height=max(550, altura_total))

    def _criar_card(self, corpo, y, credencial_id, titulo):
        """Um card por credencial (mesmo layout do f_credencial do protótipo)."""
        try:
            dados = self.gerenciador.obter(credencial_id)
            aviso = None
        except ErroDoCofre as erro:  # ex.: CredencialAdulterada
            dados = None
            aviso = str(erro)

        f_credencial = tk.Frame(corpo, relief="groove", bd=2)
        f_credencial.place(x=self.CARD_X, y=y, width=self.CARD_LARGURA, height=self.CARD_ALTURA)

        l_titulo_credencial = tk.Label(f_credencial, text=titulo, fg="#ffffff", font=("Helvetica", 12, "bold"), anchor="w")
        l_titulo_credencial.place(x=11, y=7, width=462, height=26)

        if dados is None:
            # Registro corrompido: não há o que mostrar/editar, mas dá para excluir.
            l_aviso = tk.Label(f_credencial, text=aviso, fg="#ff8a8a", wraplength=450, justify="left", anchor="w")
            l_aviso.place(x=11, y=40, width=462, height=60)
        else:
            l_dominio_senha = tk.Label(f_credencial, text=dados["site"], fg="#ffffff", font=("Helvetica", 15), anchor="w")
            l_dominio_senha.place(x=11, y=33, width=462, height=22)

            e_senha_salva = tk.Entry(f_credencial, show="*", readonlybackground=THEME_FIELD_BG)
            e_senha_salva.insert(0, dados["senha"])
            e_senha_salva.configure(state="readonly")  # dá para selecionar/copiar, não para digitar
            e_senha_salva.place(x=132, y=72, width=220, height=33)

            ocultar = tk.IntVar(value=1)
            self._variaveis_ocultar.append(ocultar)
            cb_ocultar_senha = tk.Checkbutton(
                f_credencial,
                text="ocultar",
                variable=ocultar,
                command=lambda entrada=e_senha_salva, var=ocultar: entrada.configure(show="*" if var.get() else ""),
                fg="#ffffff",
                font=("Helvetica", 9),
            )
            cb_ocultar_senha.place(x=363, y=77, width=77, height=22)

            b_editar_credencial = tk.Button(f_credencial, text="Editar", command=lambda: self.on_b_editar_credencial(credencial_id), font=("Helvetica", 10, "bold"))
            b_editar_credencial.place(x=154, y=133, width=77, height=22)

        b_excluir_credencial = tk.Button(f_credencial, text="Excluir", command=lambda: self.on_b_excluir_credencial(credencial_id), bg="#e02929", font=("Helvetica", 10, "bold"))
        b_excluir_credencial.place(x=253, y=133, width=77, height=22)

    # ----- abrir pop-ups -----

    def open_password_manager_app___criar_credencial(self):
        return PasswordManagerAppCriarCredencial(self.root, self._salvar_nova)

    def open_password_manager_app___excluir_credencial(self, credencial_id):
        return PasswordManagerAppExcluirCredencial(self.root, lambda: self._excluir(credencial_id))

    # ----- ações (falam com o core) -----

    def _salvar_nova(self, titulo, dados):
        self.gerenciador.adicionar(titulo, dados)
        self.carregar_credenciais()

    def _salvar_edicao(self, credencial_id, titulo, dados):
        self.gerenciador.editar(credencial_id, titulo, dados)
        self.carregar_credenciais()

    def _excluir(self, credencial_id):
        try:
            self.gerenciador.remover(credencial_id)
        finally:
            self.carregar_credenciais()  # atualiza a lista mesmo se já tinha sumido

    # ----- eventos -----

    def on_b_adicionar_credencial(self):
        self.open_password_manager_app___criar_credencial()

    def on_b_editar_credencial(self, credencial_id):
        try:
            credencial = self.gerenciador.obter(credencial_id)
        except ErroDoCofre as erro:
            messagebox.showerror("Não foi possível abrir", str(erro), parent=self.root)
            return
        PasswordManagerAppCriarCredencial(
            self.root,
            lambda titulo, dados: self._salvar_edicao(credencial_id, titulo, dados),
            credencial,
        )

    def on_b_excluir_credencial(self, credencial_id):
        self.open_password_manager_app___excluir_credencial(credencial_id)

    def on_b_sair(self):
        if self._fechada:
            return
        self._fechada = True
        self.gerenciador.sair()  # bloqueia o cofre: descarta a chave
        self.root.destroy()
        self._ao_sair()


# ---------------------------------------------------------------------------
# JANELA: HOME (LOGIN E CADASTRO)
# ---------------------------------------------------------------------------

class PasswordManagerAppHome:
    def __init__(self, root, gerenciador):
        self.root = root
        self.gerenciador = gerenciador
        root.title("Password Manager App - Home")
        root.geometry("800x600")
        apply_theme(root)

        self.lf_login = tk.LabelFrame(root, text="Login", relief="groove", fg="#ffffff")
        self.lf_login.place(x=132, y=33, width=539, height=253)

        self.lf_cadastro = tk.LabelFrame(root, text="Cadastro", relief="raised", fg="#ffffff")
        self.lf_cadastro.place(x=125, y=308, width=550, height=253)

        self.e_usuario_login = tk.Entry(self.lf_login)
        self.e_usuario_login.place(x=270, y=45, width=183, height=28)

        self.e_senha_login = tk.Entry(self.lf_login, show="*")
        self.e_senha_login.place(x=270, y=99, width=183, height=28)
        self.e_senha_login.bind("<Return>", lambda _e: self.on_b_confirmar_login())

        self.l_usuario_login = tk.Label(self.lf_login, text="Usuário:", fg="#ffffff", font=("Helvetica", 20))
        self.l_usuario_login.place(x=121, y=45, width=100, height=30)

        self.l_senha_login = tk.Label(self.lf_login, text="Senha:", fg="#ffffff", font=("Helvetica", 20))
        self.l_senha_login.place(x=132, y=99, width=100, height=30)

        self.b_confirmar_login = tk.Button(self.lf_login, text="Entrar", command=self.on_b_confirmar_login, fg="#ffffff", bg="#666666")
        self.b_confirmar_login.place(x=221, y=187, width=96, height=32)

        self.l_usuario_cadastro = tk.Label(self.lf_cadastro, text="Usuário:", fg="#ffffff", font=("Helvetica", 20))
        self.l_usuario_cadastro.place(x=68, y=38, width=100, height=30)

        self.l_senha_cadastro = tk.Label(self.lf_cadastro, text="Senha:", fg="#ffffff", font=("Helvetica", 20))
        self.l_senha_cadastro.place(x=66, y=100, width=100, height=30)

        self.e_usuario_cadastro = tk.Entry(self.lf_cadastro)
        self.e_usuario_cadastro.place(x=198, y=40, width=183, height=28)

        self.e_senha_cadastro = tk.Entry(self.lf_cadastro, show="*")
        self.e_senha_cadastro.place(x=198, y=103, width=183, height=28)

        self.b_confirmar_cadastro = tk.Button(self.lf_cadastro, text="Cadastrar", command=self.on_b_confirmar_cadastro, fg="#ffffff", bg="#666666")
        self.b_confirmar_cadastro.place(x=418, y=110, width=96, height=32)

        self.l_repetir_senha_cadastro = tk.Label(self.lf_cadastro, text="Repita Senha", fg="#ffffff", font=("Helvetica", 17))
        self.l_repetir_senha_cadastro.place(x=44, y=143, width=143, height=77)

        self.e_repetir_senha_cadastro = tk.Entry(self.lf_cadastro, show="*")
        self.e_repetir_senha_cadastro.place(x=198, y=167, width=183, height=28)
        self.e_repetir_senha_cadastro.bind("<Return>", lambda _e: self.on_b_confirmar_cadastro())

        self.e_usuario_login.focus_set()

    def open_password_manager_app___credenciais(self):
        return PasswordManagerAppCredenciais(self.root, self.gerenciador, self._voltar_para_home)

    def _voltar_para_home(self):
        """Chamado quando a janela de credenciais fecha (o cofre já foi bloqueado)."""
        self.root.deiconify()
        self.e_usuario_login.focus_set()

    def on_b_confirmar_login(self):
        usuario = self.e_usuario_login.get()
        senha = self.e_senha_login.get()
        try:
            with ocupado(self.root):
                self.gerenciador.entrar(usuario, senha)
        except ErroDoCofre as erro:
            messagebox.showerror("Login", str(erro), parent=self.root)
            self.e_senha_login.delete(0, "end")
            return

        self.e_usuario_login.delete(0, "end")
        self.e_senha_login.delete(0, "end")
        self.root.withdraw()  # esconde o login enquanto o cofre está aberto
        self.open_password_manager_app___credenciais()

    def on_b_confirmar_cadastro(self):
        usuario = self.e_usuario_cadastro.get()
        senha = self.e_senha_cadastro.get()
        repetida = self.e_repetir_senha_cadastro.get()

        if senha != repetida:
            messagebox.showerror("Cadastro", "As senhas não coincidem.", parent=self.root)
            return

        try:
            with ocupado(self.root):
                self.gerenciador.cadastrar(usuario, senha)
        except ErroDoCofre as erro:
            messagebox.showerror("Cadastro", str(erro), parent=self.root)
            return

        for campo in (self.e_usuario_cadastro, self.e_senha_cadastro, self.e_repetir_senha_cadastro):
            campo.delete(0, "end")

        messagebox.showinfo("Cadastro", "Usuário cadastrado! Agora é só entrar.", parent=self.root)
        self.e_usuario_login.delete(0, "end")
        self.e_usuario_login.insert(0, usuario.strip())
        self.e_senha_login.focus_set()


# ---------------------------------------------------------------------------
# INÍCIO
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    try:
        banco = Banco(CAMINHO_DO_BANCO)
    except EsquemaIncompativel as erro:
        root.withdraw()
        messagebox.showerror("Banco incompatível", str(erro), parent=root)
        root.destroy()
        return

    PasswordManagerAppHome(root, GerenciadorDeSenhas(banco))
    root.mainloop()


if __name__ == "__main__":
    main()
