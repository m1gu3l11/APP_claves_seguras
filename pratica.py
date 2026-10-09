import sqlite3
import re
import os
import logging
import json
import base64
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID

# Importamos el módulo gestor de AC1
import ac1_manager
# Parámetros de Scrypt 
SALT_SIZE = 16        # 128 bits de salt
KEY_LEN = 32          # 256 bits de hash derivado
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


# Vamos a crear direcciones, esto lo usaremos luego para las PEM, ya que asociaremos rutas a las PEM y lo guardaremos en la base de datos esta ruta
os.makedirs("secure", exist_ok=True)
os.makedirs("secure/keys", exist_ok=True)
os.makedirs("secure/certs", exist_ok=True)      
os.makedirs("secure/envelopes", exist_ok=True)
os.makedirs("secure/signature", exist_ok=True)

try:
    os.chmod("secure", 0o700)
except Exception:
    pass 

# Ahora para que se vean los logs de cada cosa, ya que la práctica pide registrar los algoritmos y longitudes usados
logging.basicConfig(
    level= logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("secure/crypto.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Crear base de datos y tabla, en ella vamos a guardar 
conn = sqlite3.connect('usuarios.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    hash_contraseña BLOB NOT NULL,
    clave_privada_ruta_pem TEXT,
    clave_publica_ruta_pem TEXT,
    certificado_ruta_pem TEXT
)
''')
conn.commit()
# Hemos usado BLOB pq la contraseña sera una secuencia de bytes, y sql si usaramos text convierte bytes a texto pero podria haber algun error
# Otros ejemplos donde se podria usar BLOB seria con la salt 
# Usamos text para las rutas pq es un texto legible 


#Función para forzar contraseñas robustas
def es_contraseña_segura(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def hash_password(password):
    """
    Deriva un hash seguro a partir de la contraseña usando Scrypt.
    Devuelve salt || hash (concatenados) para guardarlo en la BD como BLOB.
    """
    salt = os.urandom(SALT_SIZE)
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    key = kdf.derive(password.encode("utf-8"))  # bytes
    return salt + key  # 16 + 32 = 48 bytes


def verificar_contrasena(contr_guardada, contr_pasada):
    """
    Comprueba si la contraseña proporcionada coincide con el hash almacenado.
    'stored' es salt || hash guardado en la BD.
    """
    salt = contr_guardada[:SALT_SIZE]
    clave_guardada = contr_guardada[SALT_SIZE:]

    kdf = Scrypt(
        salt=salt,
        length=len(clave_guardada),
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    try:
        kdf.verify(contr_pasada.encode("utf-8"), clave_guardada)
        return True
    except InvalidKey:
        return False
    
def verificar_certificado_firmado_por_ac1(ruta_cert_usuario):
    """Verifica que el certificado del usuario fue firmado por AC1"""
    try:
        # Cargamos Certificado de AC1 (Issuer) desde la ruta definida en el manager
        with open(ac1_manager.AC1_CERT_PATH, "rb") as f:
            cert_ac1 = x509.load_pem_x509_certificate(f.read())
        
        # Cargamos Certificado del Usuario
        with open(ruta_cert_usuario, "rb") as f:
            cert_usuario = x509.load_pem_x509_certificate(f.read())

        # Comprueba que la firma digital del cert_usuario corresponde a la clave pública de cert_ac1
        cert_usuario.verify_directly_issued_by(cert_ac1)
        
        logging.info("Verificación exitosa: Certificado auténtico de AC1.")
        return True

    except ValueError as e:
        logging.error("Fallo de verificación (Issuer mismatch): %s", e)
        print("Error: El emisor no coincide.")
        return False
    except InvalidSignature:
        logging.error("Fallo de verificación: Firma inválida.")
        print("Error CRÍTICO: La firma del certificado es inválida.")
        return False
    except Exception as e:
        logging.error("Error verificando certificado: %s", e)
        return False
    
def generar_par_claves_priv_pub(usuario, passsword):
    # Usamos 65537 pq es el que recomienda NIST, y usamos 3072 que es el RSA similar a utilizar un AES-128 que es suficiente en seguridad, si metiesemos más seria mas lento y pesado
    clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    pem_privada = clave_privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passsword.encode())
    )
    clave_publica = clave_privada.public_key()
    pem_publica = clave_publica.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs("secure/keys", exist_ok=True)
    ruta_priv = f"secure/keys/{usuario}_priv.pem"
    ruta_publica = f"secure/keys/{usuario}_pub.pem"

    with open(ruta_priv, "wb") as f:
        f.write(pem_privada)
    try:
        os.chmod(ruta_priv, 0o600)  
    except Exception:
        pass
    with open(ruta_publica, "wb") as f:
        f.write(pem_publica)

    logging.info("Generado par RSA-3072 (PKCS#8 cifrada) para %s", usuario)
    return ruta_priv, ruta_publica, clave_privada

# Función para registrar usuario
def registrar_usuario(usuario: str, password: str, ac1_password: str):
    # Inicializar estructura AC1 si no existe
    ac1_manager.inicializar_estructura_ac1(ac1_password)
    if not es_contraseña_segura(password):
        print("La contraseña no es lo suficientemente segura.")
        return False

    # Generar hash con Scrypt (cryptography) y claves (rutas)
    hash_contrasena = hash_password(password)  # devuelve bytes salt||hash

    # Usaremos obj_clave_privada para firmar la solicitud CSR y evitar 
    # que otro usuario se haga pasar por este usando la clave pública de este
    ruta_priv, ruta_pub, obj_clave_privada = generar_par_claves_priv_pub(usuario, password)

    # Generar CSR (Solicitud) automatizado
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "INF"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{usuario}"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "usuario@gmail.com"),
    ])).sign(obj_clave_privada, hashes.SHA256())

    # El CSR se guarda en la carpeta de solicitudes de la AC1
    os.makedirs("AC1/solicitudes", exist_ok=True)
    ruta_csr = f"AC1/solicitudes/{usuario}.csr"
    
    # Serialización: Convertimos el objeto CSR de memoria a formato PEM (bytes) y lo guardamos
    with open(ruta_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # Firmar CSR usando OpenSSL (vía ac1_manager)
    # La función firmar_csr_con_openssl está definida en ac1_manager.py
    ruta_cert = f"secure/certs/{usuario}_cert.pem"
    firma_cert = ac1_manager.firmar_csr_con_openssl(ruta_csr, ruta_cert, ac1_password)

    if not firma_cert:
        print("Error al firmar el certificado.")
        return False

    # Verificar el certificado recién emitido
    if not verificar_certificado_firmado_por_ac1(ruta_cert):
        print("Error: El certificado no pasó la verificación de seguridad.")
        return False
    
    try:
        cursor.execute("""
            INSERT INTO usuarios (usuario, hash_contraseña, clave_privada_ruta_pem, clave_publica_ruta_pem, certificado_ruta_pem)
            VALUES (?, ?, ?, ?, ?)
        """, (usuario, sqlite3.Binary(hash_contrasena), ruta_priv, ruta_pub, ruta_cert))
        conn.commit()
        logging.info("Usuario %s registrado (Scrypt + RSA-3072 + Certificado).", usuario)
        print("Usuario registrado con éxito.")
        return True

    except sqlite3.IntegrityError:
        # Limpieza si el usuario ya existe: borrar los PEM recién creados
        try:
            if os.path.exists(ruta_priv): os.remove(ruta_priv)
            if os.path.exists(ruta_pub):  os.remove(ruta_pub)
        except Exception:
            pass
        print("El nombre de usuario ya existe.")
        return False


# Función para autenticar
def autenticar_usuario(usuario, password):
    print(f"--- DEBUG: Intentando autenticar a '{usuario}' ---")
    cursor.execute(
        "SELECT hash_contraseña FROM usuarios WHERE usuario = ?",
        (usuario,)
    )
    resultado = cursor.fetchone()
    if resultado is None:
        print("Usuario no encontrado.")
        return False
    # result[0] es el BLOB salt||hash recuperado de la BD
    guardar_contrasena = resultado[0] 
    print(f"--- DEBUG: Usuario encontrado. Longitud del hash: {len(guardar_contrasena)} bytes")

    try:
        ok = verificar_contrasena(guardar_contrasena, password)
    except Exception as e:
        print(f"--- DEBUG: Error verificando: {e}")
        ok = False

    if ok:
        print("Autenticación exitosa.")
        logging.info("Autenticación OK para %s", usuario)
    else:
        print("Credenciales incorrectas.")
        logging.info("Autenticación FALLIDA para %s", usuario)
    return ok

def cargar_clave_privada_usuario(usuario,password):
    cursor.execute("SELECT clave_privada_ruta_pem FROM usuarios where usuario=?", (usuario,))
    # Usamos fetchone que puede devolver None o la clave privada del usuario, y lo guardanis en una variable pem
    row = cursor.fetchone()
    if not row or not row[0]:
        raise ValueError("Clave privada no encontrada")
    with open(row[0], "rb") as f:
        pem = f.read()
    return serialization.load_pem_private_key(pem, password=password.encode())

def cargar_clave_publica_usuario(usuario):
    cursor.execute("SELECT clave_publica_ruta_pem FROM usuarios WHERE usuario=?", (usuario,))
    # Aqui al igual que en la funcion de arriba, fechone nos devuelve o NOne o la clave que queremos y la guardamos en una variable pem
    row = cursor.fetchone()
    if not row or not row[0]:
        raise ValueError("Clave pública no encontrada.")
    with open(row[0], "rb") as f:
        pem = f.read()
    return serialization.load_pem_public_key(pem)

def cargar_ruta_certificado_usuario(usuario):
    """Función para cargar la ruta del certificado PEM del usuario"""
    cursor.execute("SELECT certificado_ruta_pem FROM usuarios WHERE usuario=?", (usuario,))
    row = cursor.fetchone()
    if not row or not row[0]: raise ValueError("Certificado no encontrado.")
    return row[0]



def cifrar_para_usuario(usuario_dest, ruta_in, ruta_sobre, aad):
    """
    - Genera clave simétrica efímera AES-256
    - Cifra con AES-GCM (nonce 12B, AAD opcional)
    - Envuelve la clave con la pública RSA del destinatario (OAEP-SHA256)
    - Guarda 'sobre' JSON: alg, nonce, aad, wrapped_key, ciphertext
    """
    publica = cargar_clave_publica_usuario(usuario_dest)

    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    aad_b = aad or b""

    with open(ruta_in, "rb") as f:
        datos = f.read()

    cifrado = aes.encrypt(nonce, datos, aad_b)

    clave_envuelta = publica.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    paquete = {
        "alg": "AES-256-GCM + RSA-3072-OAEP",
        "nonce": base64.b64encode(nonce).decode(),
        "aad": base64.b64encode(aad_b).decode() if aad_b else "",
        "clave_envuelta": base64.b64encode(clave_envuelta).decode(),
        "texto": base64.b64encode(cifrado).decode()
    }

    with open(ruta_sobre, "w") as f:
        f.write(json.dumps(paquete))

    logging.info("Híbrido: AES-256-GCM(key=256b) + RSA-OAEP(SHA-256), nonce=12B, dest=%s, sobre=%s",
                 usuario_dest, ruta_sobre)
    print(f"Archivo cifrado para {usuario_dest}. Sobre: {ruta_sobre}")
    return ruta_sobre

def descifrar_para_usuario(usuario, password_login, ruta_sobre, ruta_out):
    """
    - Autentica al usuario
    - Desbloquea su privada RSA (PEM cifrada con su contraseña)
    - Unwrap de la clave con RSA-OAEP
    - Descifra con AES-GCM y escribe 'ruta_out'
    """
    if not autenticar_usuario(usuario, password_login):
        print("Credenciales incorrectas.")
        return False

    try:
        with open(ruta_sobre, "r") as f:
            paquete = json.loads(f.read())
        nonce = base64.b64decode(paquete["nonce"])
        aad_b = base64.b64decode(paquete["aad"]) if paquete.get("aad") else b""
        wrapped_key = base64.b64decode(paquete["clave_envuelta"])
        cifrado = base64.b64decode(paquete["texto"])
    except Exception as e:
        print("Sobre inválido (formato/JSON).")
        logging.error("Sobre inválido: %s", e)
        return False

    try:
        priv = cargar_clave_privada_usuario(usuario, password_login)
        key = priv.decrypt(
            wrapped_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        texto = AESGCM(key).decrypt(nonce, cifrado, aad_b)
    except Exception as e:
        print("Error: sobre corrupto o destinatario incorrecto.")
        logging.error("Fallo descifrado híbrido: %s", e)
        return False

    with open(ruta_out, "wb") as f:
        f.write(texto)

    logging.info("Descifrado híbrido OK (usuario=%s, out=%s)", usuario, ruta_out)
    print(f"Sobre descifrado por {usuario}. Archivo: {ruta_out}")
    return True

def generar_firma(usuario, password, ruta_archivo):
    """ En esta funcion lo que vamos a hacer es:
    - cargar las claves privadas ya generadas en una función
    - generar la firma 
    - pasarsela al archivo para que quede con la firma del usuario que envia
    """
    try:
        clave_privada = cargar_clave_privada_usuario(usuario, password)

    except Exception as e:
        print("Fallo al cargar la clave privada")
        logging.error("Fallo al cargar la clave privada")
        return
    try:
        with open(ruta_archivo, "rb") as f:
            data = f.read()
    except FileNotFoundError as e:
        print("Error cargando los datos")
        logging.error("Datos mal leidos")
        return
    try:
        firma = clave_privada.sign(
            data, 
            # PSS es el relleno válido usado en la firma 
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    except Exception:
        print("Error en la generación de la firma")
        logging.error("Fallo en la firma") 
        return

    logging.info("Se ha generado la firma correctamente")
    return firma


""" Al haber creado ahora una generacion de firma, tenemos que modificar la logica de la creacion de archivos ya que hay que asociar la firma a cada archivo
 Por tanto en una función general vamos a juntar el cifrado del sobre con la generacion de la firma"""
def crear_sobre(usuario_dest, ruta_in,ruta_sobre,add, usuario_orig, password_orig):
    # Si no existe la ruta del sobre, la creamos en secure/envelopes
    if ruta_sobre is None:
        os.makedirs("secure/envelopes", exist_ok=True)
        ruta_sobre = f"secure/envelopes/{usuario_dest}_{secrets.token_hex(8)}.env"
    firma = generar_firma(usuario_orig, password_orig,ruta_in)
    if firma is None:
        print("No se puede generar la firma")
        return 
    
    os.makedirs(f"secure/signature", exist_ok=True)
    nombre_sobre = os.path.basename(ruta_sobre)
    ruta_de_firma = f"secure/signature/{nombre_sobre}.sig"

    with open (ruta_de_firma, "wb") as f:
        f.write(firma)
    try:
        os.chmod(ruta_de_firma, 0o600)
    except Exception:
        pass

    cifrar_para_usuario(usuario_dest, ruta_in, ruta_sobre, add)
    print("Se ha creado correctamente el archivo")
    logging.info("Archivo %s cifrado correctamente con la firma", ruta_sobre)
    return True


""" Ahora vamos con la verificación de la firma que esta servirá para que el que recibe un archivo comprueba que de verdad la firma corresponde al otro 
usuario"""
def verificar_firma(usuario_orig, ruta_archivo, ruta_firma):
    # Necesito cargar o de alguna manera coger la firma del sobre para verificar si la firma pertenece a ese usuario, logica inversa a crear el sobre
    # Todo esto pq en .verify necesito : la firma y el mensaje 
    # Cargando la ruta_archivo ya tengo esa parte del mensaje 
    with open(ruta_archivo, "rb") as f:
        datos = f.read()
    
    # Cargando ruta_firma consigo la firma
    with open(ruta_firma, "rb") as f:
        firma = f.read()

    try:
        # Obtenemos la ruta del certificado del usuario
        ruta_cert_usuario = cargar_ruta_certificado_usuario(usuario_orig)
        
        # Usamos la función de verificación de si la firma fue creada por AC1
        if not verificar_certificado_firmado_por_ac1(ruta_cert_usuario):
            print(f"Firma rechazada: El certificado de {usuario_orig} no está firmado por AC1.")
            return False

        # Cargar el certificado para extraer su clave pública
        # Esto es más seguro que cargar la clave pública suelta, porque el certificado ya ha sido verificado
        with open(ruta_cert_usuario, "rb") as f:
            cert_usuario = x509.load_pem_x509_certificate(f.read())
            clave_publica = cert_usuario.public_key()
        # Verificar la firma con la clave pública del certificado
        clave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )  
    except Exception:
        print("Error por clave inexistente")
        logging.error("Firma incorrecta")
        return False
    logging.info("La firma pertenece al usuario: %s",usuario_orig)
    return True
    
def descifrar_sobre(usuario_dest, password_dest, ruta_sobre, ruta_out, usuario_orig):
    """ Sobre esta función vamos a hacer la operación inversa que en crear_sobre donde verificaremos la firma y descifraremos el archivo mandado """
    # Por tanto primero llamamos a descifrar archivo
    if not descifrar_para_usuario(usuario_dest, password_dest, ruta_sobre, ruta_out):
        return False
    
    nombre_sobre = os.path.basename(ruta_sobre)          
    ruta_firma = f"secure/signature/{nombre_sobre}.sig"

    verificacion = verificar_firma(usuario_orig, ruta_out, ruta_firma)
    if not verificacion:
        print("La firma no es válida o hay un error de verificación ")
        logging.error("Verificación de firma fallida")
        return
    print("Archivo descifrado y firma verificada")
    logging.info("Archivo %s descifrado y firma OK", ruta_sobre)
    return True
