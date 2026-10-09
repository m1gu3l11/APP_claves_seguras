import os
import sqlite3
import tkinter as tk
import time
import os
import logging
import re # Importamos el módulo de expresiones regulares
from tkinter import ttk, filedialog, messagebox, simpledialog

# --- Importa TU lógica criptográfica ---
# Debe existir pratica.py con:
#  - autenticar_usuario(username, password) -> bool
#  - generar_clave(password, salt=None) -> (key: bytes, salt: bytes)
#  - generar_par_claves_priv_pub(username, password)  (opcional, para preparar híbrido)
#  - (opcional) cifrar_para_usuario(dest_username, ruta_in, envelope_out=None, aad=b"")
#  - (opcional) descifrar_sobre(username, password, envelope_path, ruta_out)
import pratica as cr

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================
# FUNCIÓN DE SEGURIDAD DE CONTRASEÑA
# ==========================================
def es_contraseña_segura(password):
    """
    Valida que la contraseña cumpla con los criterios mínimos de seguridad:
    - Mínimo 8 caracteres.
    - Al menos una mayúscula.
    - Al menos una minúscula.
    - Al menos un dígito.
    - Al menos un carácter especial.
    """
    if len(password) < 8:
        return False
    # Revisa mayúscula
    if not re.search(r"[A-Z]", password):
        return False
    # Revisa minúscula
    if not re.search(r"[a-z]", password):
        return False
    # Revisa dígito
    if not re.search(r"[0-9]", password):
        return False
    # Revisa carácter especial
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def _db_path_from_pratica():
    # Intenta obtener la ruta real del archivo abierto por pratica.py
    try:
        if hasattr(cr, "conn"):
            row = cr.conn.execute("PRAGMA database_list").fetchone()
            if row and len(row) >= 3 and row[2]:
                return row[2]  # ruta absoluta al .db
    except Exception:
        pass
    return "usuarios.db"  # fallback

DB_PATH = _db_path_from_pratica()

ENVELOPES_DIR = "secure/envelopes"
os.makedirs(ENVELOPES_DIR, exist_ok=True)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Criptografía — Práctica (AES-GCM & RSA-OAEP)")
        self.user = None
        self.session_pwd = None

        self._build_login()

    def _build_login(self):
        # Limpia cualquier cosa anterior (por si venimos de cerrar sesión)
        for w in self.root.winfo_children():
            w.destroy()

        # Frame contenedor que ocupa toda la ventana
        outer = ttk.Frame(self.root, padding=20)
        outer.pack(fill="both", expand=True)

        # Frame interior CENTRADO dentro de outer
        wrap = ttk.Frame(outer, padding=14)
        # relx/rely = 0.5 -> centro; anchor="center" -> centrado
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(wrap, text="Usuario:").grid(row=0, column=0, sticky="e", pady=4, padx=(0, 8))
        self.ent_user = ttk.Entry(wrap, width=30)
        self.ent_user.grid(row=0, column=1, sticky="w")

        ttk.Label(wrap, text="Contraseña:").grid(row=1, column=0, sticky="e", pady=4, padx=(0, 8))
        self.ent_pass = ttk.Entry(wrap, width=30, show="*")
        self.ent_pass.grid(row=1, column=1, sticky="w")

        btns = ttk.Frame(wrap)
        btns.grid(row=2, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(btns, text="Iniciar sesión", command=self._do_login).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Registrar usuario", command=self._do_register).grid(row=0, column=1)

        for i in range(2):
            wrap.columnconfigure(i, weight=1)

    def _logout(self):
        """Cierra sesión y vuelve a la pantalla de login."""
        self.user = None
        self.session_pwd = None
        self._build_login()

    # ========== Acciones de login/registro ==========
    def _do_login(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        try:
            if cr.autenticar_usuario(u, p):
                self.user = u
                self.session_pwd = p
                self._build_main()
            else:
                messagebox.showerror("Login", "Credenciales incorrectas.")
        except Exception as e:
            messagebox.showerror("Login", f"Error al autenticar: {e}")

    def _do_register(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        if not u or not p:
            messagebox.showwarning("Aviso", "Rellena usuario y contraseña.")
            return

        # --- GESTIÓN DE CONTRASEÑA AC1 (CRÍTICO) ---
        # Necesitamos la contraseña de la Autoridad para firmar el certificado del nuevo usuario
        ac1_key_path = "AC1/privado/ca1key.pem"
        ac1_exists = os.path.exists(ac1_key_path)
        
        if not ac1_exists:
            # Caso 1: No existe la AC1, pedimos crear una contraseña nueva
            msg = " Configuración Inicial AC1 \n\nLa Autoridad no existe.\nCrea una contraseña MAESTRA para ella:"
        else:
            # Caso 2: Ya existe, pedimos la contraseña para usarla
            msg = " Seguridad PKI \n\nIntroduce la contraseña de la AC1\npara firmar el certificado:"

        ac1_pwd = simpledialog.askstring("Autoridad de Certificación", msg, show='*')
        
        if not ac1_pwd: 
            return # Cancelar si el usuario cierra el diálogo o lo deja vacío
        
        if not es_contraseña_segura(ac1_pwd):
            messagebox.showerror("Contraseña AC1 insegura",
                                 "La contraseña de AC1 debe seguir los estándares de seguridad"
            )
            return

        # --- REGISTRO ---
        # Usamos "watch" en lugar de "wait" por compatibilidad en sistemas Linux/Tcl
        self.root.config(cursor="watch")
        self.root.update()
        
        try:
            # Llamamos a registrar pasando la contraseña de la AC1
            exito = cr.registrar_usuario(u, p, ac1_pwd)
            self.root.config(cursor="")
            
            if exito:
                messagebox.showinfo("Éxito", f"Usuario '{u}' registrado.\nCertificado emitido y firmado por AC1.")
            else:
                messagebox.showerror("Error", "No se pudo registrar.\nPosible causa: Contraseña de AC1 incorrecta o usuario duplicado.")
        except Exception as e:
            self.root.config(cursor="")
            messagebox.showerror("Error Crítico", f"{e}")

    # ========== Construcción de pestañas ==========
    def _build_main(self):
        # Limpia la ventana
        for w in self.root.winfo_children():
            w.destroy()

        # Barra superior con usuario + botón cerrar sesión
        top_bar = ttk.Frame(self.root, padding=(10, 5))
        top_bar.pack(fill="x")

        ttk.Label(top_bar, text=f"Usuario conectado: {self.user}").pack(side="left")
        ttk.Button(top_bar, text="Cerrar sesión", command=self._logout).pack(side="right")

        # Notebook principal
        nb = ttk.Notebook(self.root)
        nb.bind("<<NotebookTabChanged>>", lambda e: self._refresh_destinatarios())
        nb.pack(fill="both", expand=True)

        self._tab_compartir_hibrido(nb)
        self._tab_recibidos(nb)
        self._tab_enviados(nb)

    def _refresh_destinatarios(self):
        try:
            users = self._listar_usuarios_sin_yo()
            self.cmb_dest['values'] = users
            # auto-seleccionar el primero si hay alguno y no hay selección
            if users and not self.var_dest.get():
                self.cmb_dest.set(users[0])
            if not users:
                self.cmb_dest.set("")  # limpia selección si no hay
        except Exception as e:
            messagebox.showerror("Destinatarios", f"No se pudo cargar la lista: {e}")



    # ---------- 2) Compartir (híbrido) ----------
    def _tab_compartir_hibrido(self, nb: ttk.Notebook):
        tab = ttk.Frame(nb)
        nb.add(tab, text="Compartir (híbrido)")

        # --- Enviar archivo (híbrido) ---
        send_box = ttk.LabelFrame(tab, text="Enviar archivo (híbrido)", padding=10)
        send_box.grid(row=0, column=0, sticky="nwe", padx=10, pady=10)
        send_box.columnconfigure(1, weight=1)

        ttk.Label(send_box, text="Destinatario:").grid(row=0, column=0, sticky="w", padx=(0,6))
        self.var_dest = tk.StringVar()
        self.cmb_dest = ttk.Combobox(send_box, textvariable=self.var_dest, width=28, state="readonly",
                                    values=self._listar_usuarios_sin_yo())
        self.cmb_dest.grid(row=0, column=1, sticky="we")

        ttk.Label(send_box, text="Archivo a enviar:").grid(row=1, column=0, sticky="w", pady=(8,0), padx=(0,6))
        self.ent_share_in = ttk.Entry(send_box, width=60)
        self.ent_share_in.grid(row=1, column=1, sticky="we", pady=(8,0))
        ttk.Button(send_box, text="Seleccionar...", command=self._pick_share_in).grid(row=1, column=2, padx=6)

        ttk.Button(send_box, text="Enviar (híbrido)", command=self._do_enviar_hibrido)\
        .grid(row=2, column=2, sticky="e", pady=10)

        # --- Abrir archivo recibido ---
        open_box = ttk.LabelFrame(tab, text="Abrir archivo recibido", padding=10)
        open_box.grid(row=1, column=0, sticky="nwe", padx=10, pady=10)
        open_box.columnconfigure(1, weight=1)

        ttk.Label(open_box, text="Sobre recibido (.env):").grid(row=0, column=0, sticky="w", padx=(0,6))
        self.var_env_path = tk.StringVar()
        self.ent_env = ttk.Entry(open_box, textvariable=self.var_env_path, width=60)
        self.ent_env.grid(row=0, column=1, sticky="we")
        ttk.Button(open_box, text="Seleccionar...", command=self._pick_env).grid(row=0, column=2, padx=6)

        ttk.Label(open_box, text="Guardar como:").grid(row=1, column=0, sticky="w", pady=(8,0), padx=(0,6))
        self.ent_env_out = ttk.Entry(open_box, width=60)
        self.ent_env_out.grid(row=1, column=1, sticky="we", pady=(8,0))
        ttk.Button(open_box, text="Destino...", command=self._pick_env_out).grid(row=1, column=2, padx=6)

        ttk.Button(open_box, text="Abrir", command=self._do_descifrar_hibrido)\
        .grid(row=2, column=2, sticky="e", pady=10)

        self._refresh_destinatarios()
        ttk.Button(send_box, text="Actualizar", command=self._refresh_destinatarios)\
        .grid(row=0, column=3, padx=6)
        tab.columnconfigure(0, weight=1)

    def _do_enviar_hibrido(self):
        dest = self.var_dest.get().strip()
        ruta_in = self.ent_share_in.get().strip()
        if not dest or not ruta_in:
            messagebox.showwarning("Enviar (híbrido)", "Elige destinatario y archivo.")
            return
        try:
            os.makedirs(ENVELOPES_DIR, exist_ok=True)
            # Nombre del sobre: timestamp__origen__to__dest.env
            env_path = os.path.join(
                ENVELOPES_DIR,
                f"{int(time.time())}__{self.user}__to__{dest}.env"
            )

            res = False

            # 1) Si tienes crear_sobre (firma + cifrado), la usamos
            if hasattr(cr, "crear_sobre"):
                res = cr.crear_sobre(dest, ruta_in, env_path, b"", self.user, self.session_pwd)

            else:
                raise AttributeError("No existe 'crear_sobre', 'enviar_archivo_hibrido' ni 'cifrar_para_usuario' en pratica.py")

            if not res:
                raise RuntimeError("No se pudo enviar el archivo.")
            messagebox.showinfo("Enviar (híbrido)", f"Archivo enviado a {dest}.")
            self._refresh_enviados()
        except Exception as e:
            messagebox.showerror("Enviar (híbrido)", f"Error al enviar: {e}")

    # ---------- 3) Recibidos ----------
    def _tab_recibidos(self, nb: ttk.Notebook):
        tab = ttk.Frame(nb)
        nb.add(tab, text="Recibidos")

        wrap = ttk.Frame(tab, padding=10); wrap.pack(fill="both", expand=True)
        self.lst_recibidos = tk.Listbox(wrap, height=12)
        self.lst_recibidos.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.lst_recibidos.yview)
        sb.pack(side="right", fill="y")
        self.lst_recibidos.config(yscrollcommand=sb.set)

        ttk.Button(tab, text="Actualizar", command=self._refresh_recibidos).pack(anchor="e", padx=10, pady=6)
        self._refresh_recibidos()

    # ---------- 4) Enviados ----------
    def _tab_enviados(self, nb: ttk.Notebook):
        tab = ttk.Frame(nb)
        nb.add(tab, text="Enviados")

        wrap = ttk.Frame(tab, padding=10); wrap.pack(fill="both", expand=True)
        self.lst_enviados = tk.Listbox(wrap, height=12)
        self.lst_enviados.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.lst_enviados.yview)
        sb.pack(side="right", fill="y")
        self.lst_enviados.config(yscrollcommand=sb.set)

        ttk.Button(tab, text="Actualizar", command=self._refresh_enviados).pack(anchor="e", padx=10, pady=6)
        self._refresh_enviados()

    # ========== Utilidades GUI ==========
    def _pick_in(self):
        p = filedialog.askopenfilename()
        if p: self.ent_in.delete(0, tk.END); self.ent_in.insert(0, p)

    def _pick_out(self):
        p = filedialog.asksaveasfilename(defaultextension=".enc")
        if p: self.ent_out.delete(0, tk.END); self.ent_out.insert(0, p)

    def _pick_share_in(self):
        p = filedialog.askopenfilename()
        if p: self.ent_share_in.delete(0, tk.END); self.ent_share_in.insert(0, p)

    def _pick_env(self):
        p = filedialog.askopenfilename(initialdir=ENVELOPES_DIR, filetypes=[("Sobres", "*.env"), ("Todos", "*.*")])
        if p: self.var_env_path.set(p)

    def _pick_env_out(self):
        p = filedialog.asksaveasfilename()
        if p: self.ent_env_out.delete(0, tk.END); self.ent_env_out.insert(0, p)

    # ========== Listados ==========
    def _listar_usuarios_sin_yo(self):
        """Lee los usuarios de la BD (detecta nombre de columna)."""
        try:
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            # Detectar cómo se llama la columna de usuario
            cur.execute("PRAGMA table_info(usuarios)")
            cols = [row[1] for row in cur.fetchall()]
            if "usuario" in cols:
                col_name = "usuario"
            elif "username" in cols:
                col_name = "username"
            else:
                raise ValueError("No se encuentra columna de nombre de usuario en la tabla.")
            # Leer todos los usuarios
            cur.execute(f"SELECT {col_name} FROM usuarios")
            users = [r[0] for r in cur.fetchall()]
            con.close()
            # Filtrar para que no aparezca el propio usuario conectado
            return [u for u in users if u != self.user]
        except Exception as e:
            logging.exception("Error al listar usuarios: %s", e)
            return []

    def _refresh_recibidos(self):
        self.lst_recibidos.delete(0, tk.END)
        if not os.path.isdir(ENVELOPES_DIR) or not self.user:
            return

        for f in sorted(os.listdir(ENVELOPES_DIR)):
            path = os.path.join(ENVELOPES_DIR, f)
            origen, dest = self._parse_envelope_name(f)
            # Solo muestro sobres cuyo destinatario soy yo
            if dest == self.user:
                self.lst_recibidos.insert(tk.END, path)


    def _refresh_enviados(self):
        self.lst_enviados.delete(0, tk.END)
        if not os.path.isdir(ENVELOPES_DIR) or not self.user:
            return

        for f in sorted(os.listdir(ENVELOPES_DIR)):
            path = os.path.join(ENVELOPES_DIR, f)
            origen, dest = self._parse_envelope_name(f)
            # Solo muestro sobres cuyo origen soy yo
            if origen == self.user:
                self.lst_enviados.insert(tk.END, path)

    # ========== Acciones (conexión con tu cripto) ==========
    def _do_cifrar_pwd(self):
        ruta_in = self.ent_in.get().strip()
        ruta_out = self.ent_out.get().strip() or self._auto_out_path(ruta_in, "enc")
        ruta_out = self._unique_path(ruta_out)
        if not ruta_in:
            messagebox.showwarning("Cifrado", "Selecciona archivo de entrada.")
            return

        # 1) Clave desde contraseña
        if self.var_use_session_pwd.get():
            password = self.session_pwd
        else:
            password = self._pedir_pwd("Introduce la contraseña para cifrar:")
            if password is None: return

        try:
            key, salt = cr.generar_clave(password)     # PBKDF2-HMAC-SHA3-256
            aes = AESGCM(key)
            nonce = os.urandom(12)

            with open(ruta_in, "rb") as f: pt = f.read()
            ct = aes.encrypt(nonce, pt, b"")

            with open(ruta_out, "wb") as f:
                f.write(salt + nonce + ct)            # [salt(16)] [nonce(12)] [ct+tag]

            messagebox.showinfo("Cifrado", "Archivo cifrado (AES-256-GCM).")
            logging.info("Cifrado con contraseña: AES-256-GCM")
        except Exception as e:
            messagebox.showerror("Cifrado", f"Error cifrando: {e}")

    def _do_descifrar_pwd(self):
        ruta_in = self.ent_in.get().strip()
        ruta_out = self.ent_out.get().strip() or self._auto_out_path(ruta_in, "dec")
        ruta_out = self._unique_path(ruta_out)
        if not ruta_in:
            messagebox.showwarning("Descifrado", "Selecciona archivo de entrada.")
            return
        if self.var_use_session_pwd.get():
            password = self.session_pwd
        else:
            password = self._pedir_pwd("Introduce la contraseña para descifrar:")
            if password is None: return

        try:
            with open(ruta_in, "rb") as f:
                blob = f.read()
            if len(blob) < 28:
                raise ValueError("Formato inválido")
            salt, nonce, ct = blob[:16], blob[16:28], blob[28:]

            key, _ = cr.generar_clave(password, salt=salt)
            pt = AESGCM(key).decrypt(nonce, ct, b"")

            with open(ruta_out, "wb") as f:
                f.write(pt)

            logging.info("Descifrado con contraseña: AES-256-GCM")
            messagebox.showinfo("Descifrado", "Archivo descifrado (AES-256-GCM).")
        except Exception as e:
            messagebox.showerror("Descifrado", f"Error descifrando: {e}")


    def _do_descifrar_hibrido(self):
        env_path = self.var_env_path.get().strip()
        out_path = self.ent_env_out.get().strip()
        if not env_path or not out_path:
            messagebox.showwarning("Abrir sobre", "Selecciona sobre y destino.")
            return
        try:
            if not hasattr(cr, "descifrar_sobre"):
                messagebox.showwarning("Híbrido",
                    "Falta implementar 'descifrar_sobre' en pratica.py."
                )
                return

            # Extraer usuario origen del nombre del sobre: timestamp__origen__to__dest.env
            base = os.path.basename(env_path)
            partes = base.split("__")
            if len(partes) < 3:
                raise ValueError(f"No se puede obtener el emisor a partir del nombre del sobre: {base}")
            usuario_orig = partes[1]

            res = cr.descifrar_sobre(self.user, self.session_pwd, env_path, out_path, usuario_orig)
            if not res:
                messagebox.showerror("Abrir sobre", "No se ha podido descifrar/verificar el sobre.")
                return

            messagebox.showinfo("Abrir sobre", f"Archivo recuperado y firma verificada:\n{out_path}")
            self._refresh_recibidos()
        except Exception as e:
            messagebox.showerror("Abrir sobre", f"Error al abrir sobre: {e}")


    def _parse_envelope_name(self, filename: str):
        """
        Espera nombres del tipo: <ts>__<origen>__to__<dest>.env
        Devuelve (origen, dest) o (None, None) si no cuadra.
        """
        base = os.path.basename(filename)
        # Ejemplo: "1717432987__pepe__to__ana.env"
        if "__to__" not in base or "__" not in base:
            return None, None

        try:
            ts, origen, resto = base.split("__", 2)
        except ValueError:
            return None, None

        if not resto.startswith("to__"):
            return None, None

        dest = resto[4:]  # quitar "to__"
        if dest.endswith(".env"):
            dest = dest[:-4]

        return origen, dest

    # ========== Helpers ==========
    def _pedir_pwd(self, prompt: str):
        # diálogo simple para pedir contraseña (sin dependencias extra)
        top = tk.Toplevel(self.root)
        top.title("Password")
        ttk.Label(top, text=prompt, padding=8).pack(anchor="w")
        ent = ttk.Entry(top, show="*", width=32); ent.pack(padx=8, pady=4)
        ent.focus()
        out = {"pwd": None}

        def ok():
            out["pwd"] = ent.get()
            top.destroy()
        def cancel():
            out["pwd"] = None
            top.destroy()
        btns = ttk.Frame(top); btns.pack(pady=6)
        ttk.Button(btns, text="Aceptar", command=ok).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancelar", command=cancel).pack(side="left", padx=6)
        top.grab_set(); top.wait_window()
        return out["pwd"]


    def _auto_out_path(self, input_path: str, op: str) -> str:
        """Genera una ruta de salida según la operación ('enc' o 'dec')."""
        if not input_path:
            return ""
        dir_, base = os.path.split(input_path)
        if op == "enc":
            # ejemplo: foto.jpg -> foto.jpg.enc
            return os.path.join(dir_, base + ".enc")
        else:  # dec
            # ejemplo: documento.pdf.enc -> documento.pdf
            if base.endswith(".enc"):
                return os.path.join(dir_, base[:-4])
            # si no termina en .enc, sugiero .dec
            return os.path.join(dir_, base + ".dec")

    def _unique_path(self, path: str) -> str:
        """Evita sobrescribir: añade sufijos _1, _2... si existe."""
        if not os.path.exists(path):
            return path
        root, ext = os.path.splitext(path)
        i = 1
        while True:
            candidate = f"{root}_{i}{ext}"
            if not os.path.exists(candidate):
                return candidate
            i += 1


if __name__ == "__main__":
    root = tk.Tk()

    # Tamaño inicial cómodo
    root.geometry("1000x650")
    root.minsize(800, 500)

    # (Opcional) Maximizar directamente la ventana
    try:
        root.state("zoomed")           # Windows
    except Exception:
        root.attributes("-zoomed", True)  # Linux/otros

    App(root)
    root.mainloop()