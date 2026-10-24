# Designed with https://visualtkinter.com - paste this file into File > Import there to edit it visually
import tkinter as tk
from tkinter import ttk


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

    def _on_body(self, _event=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))


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


class PasswordManagerAppHome:
    def __init__(self, root):
        self.root = root
        root.title("Password Manager App - Home")
        root.geometry("800x600")
        root.update_idletasks()
        root.geometry(
            f"+{(root.winfo_screenwidth() - 800) // 2}"
            f"+{(root.winfo_screenheight() - 600) // 2}"
        )
        apply_theme(root)

        self.lf_login = tk.LabelFrame(root, text="Login", relief="groove", fg="#ffffff")
        self.lf_login.place(x=132, y=33, width=539, height=253)

        self.lf_cadastro = tk.LabelFrame(root, text="Cadastro", relief="raised", fg="#ffffff")
        self.lf_cadastro.place(x=125, y=308, width=550, height=253)

        self.e_usuario_login = tk.Entry(self.lf_login)
        self.e_usuario_login.place(x=270, y=45, width=183, height=28)

        self.e_senha_login = tk.Entry(self.lf_login, show="*")
        self.e_senha_login.place(x=270, y=99, width=183, height=28)

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

        self.entry3 = tk.Entry(self.lf_cadastro)
        self.entry3.place(x=198, y=40, width=183, height=28)

        self.entry4 = tk.Entry(self.lf_cadastro, show="*")
        self.entry4.place(x=198, y=103, width=183, height=28)

        self.b_confirmar_cadastro = tk.Button(self.lf_cadastro, text="Cadastrar", command=self.on_b_confirmar_cadastro, fg="#ffffff", bg="#666666")
        self.b_confirmar_cadastro.place(x=418, y=110, width=96, height=32)

        self.l_repetir_senha_cadastro = tk.Label(self.lf_cadastro, text="Repita Senha", fg="#ffffff", font=("Helvetica", 17))
        self.l_repetir_senha_cadastro.place(x=44, y=143, width=143, height=77)

        self.entry5 = tk.Entry(self.lf_cadastro, show="*")
        self.entry5.place(x=198, y=167, width=183, height=28)

    def open_password_manager_app___credenciais(self):
        return PasswordManagerAppCredenciais(self.root)

    def open_password_manager_app___excluir_credencial(self):
        return PasswordManagerAppExcluirCredencial(self.root)

    def open_password_manager_app___criar_credencial(self):
        return PasswordManagerAppCriarCredencial(self.root)

    def on_b_confirmar_login(self):
        pass

    def on_b_confirmar_cadastro(self):
        pass


class PasswordManagerAppCredenciais:
    def __init__(self, master):
        root = tk.Toplevel(master)
        self.root = root
        root.title("Password Manager App - Credenciais")
        root.geometry("800x600")
        root.update_idletasks()
        root.geometry(
            f"+{(root.winfo_screenwidth() - 800) // 2}"
            f"+{(root.winfo_screenheight() - 600) // 2}"
        )
        apply_theme(root)

        self.cb_ocultar_senha_var = tk.IntVar()

        self.sf_opcoes = ScrollableFrame(root)
        self.sf_opcoes.place(x=0, y=0, width=800, height=594)

        self.f_credencial = tk.Frame(self.sf_opcoes.body, relief="groove", bd=2)
        self.f_credencial.place(x=154, y=22, width=484, height=176)

        self.l_titulo_credencial = tk.Label(self.f_credencial, text="Pessoal", fg="#ffffff")
        self.l_titulo_credencial.place(x=11, y=7, width=90, height=26)

        self.l_dominio_senha = tk.Label(self.f_credencial, text="www.site.dominio.web", fg="#ffffff", font=("Helvetica", 15))
        self.l_dominio_senha.place(x=11, y=33, width=462, height=22)

        self.e_senha_salva = tk.Entry(self.f_credencial, show="*")
        self.e_senha_salva.place(x=132, y=72, width=220, height=33)

        self.cb_ocultar_senha = tk.Checkbutton(self.f_credencial, text="ocultar", variable=self.cb_ocultar_senha_var, fg="#ffffff", font=("Helvetica", 9))
        self.cb_ocultar_senha.place(x=363, y=77, width=77, height=22)

        self.b_editar_credencial = tk.Button(self.f_credencial, text="Editar", command=self.on_b_editar_credencial)
        self.b_editar_credencial.place(x=154, y=133, width=77, height=22)

        self.b_excluir_credencial = tk.Button(self.f_credencial, text="Excluir", command=self.on_b_excluir_credencial, bg="#e02929")
        self.b_excluir_credencial.place(x=253, y=133, width=77, height=22)

        self.sf_opcoes.body.configure(width=784, height=594)

    def on_b_editar_credencial(self):
        pass

    def on_b_excluir_credencial(self):
        pass


class PasswordManagerAppExcluirCredencial:
    def __init__(self, master):
        root = tk.Toplevel(master)
        self.root = root
        root.title("Password Manager App - Excluir Credencial")
        root.geometry("400x250")
        apply_theme(root)

        self.label1 = tk.Label(root, text="Tem certeza que deseja excluir essa credencial? (irreversível)", fg="#ffffff", font=("Helvetica", 15))
        self.label1.place(x=52, y=66, width=297, height=77)

        self.b_confirma_excluir = tk.Button(root, text="Excluir", command=self.on_b_confirma_excluir, fg="#ffffff", bg="#921717")
        self.b_confirma_excluir.place(x=88, y=154, width=96, height=32)

        self.button2 = tk.Button(root, text="Cancelar", command=self.on_button2, fg="#ffffff", bg="#46883f")
        self.button2.place(x=209, y=154, width=96, height=32)

    def on_b_confirma_excluir(self):
        pass

    def on_button2(self):
        pass


class PasswordManagerAppCriarCredencial:
    def __init__(self, master):
        root = tk.Toplevel(master)
        self.root = root
        root.title("Password Manager App - Criar credencial")
        root.geometry("520x380")
        apply_theme(root)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerAppHome(root)
    root.mainloop()
