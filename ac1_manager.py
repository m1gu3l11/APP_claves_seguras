import os
import logging
import subprocess

# --- CONFIGURACIÓN DE LA CA ---
ID_ALUMNO = "12345"             # Tus dígitos
CNF_PATH = "AC1/openssl_AC1.cnf"
AC1_CERT_PATH = "AC1/ac1cert.pem"

def crear_archivo_configuracion_si_no_existe():
    if os.path.exists(CNF_PATH):
        return

    os.makedirs("AC1", exist_ok=True)
    
    # Contenido del openssl.cnf
    contenido_cnf = f"""
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.

HOME            = .
RANDFILE        = $ENV::HOME/.rnd
oid_section     = new_oids

[ new_oids ]
# We can add new OIDs in here for use by 'ca' and 'req'.

####################################################################
[ ca ]
default_ca  = CA_default        # The default ca section

####################################################################
[ CA_default ]

dir     = ./AC1     # Where everything is kept
certs       = $dir/certificados # Where the issued certs are kept
crl_dir     = $dir/crls     # Where the issued crl are kept
database    = $dir/index.txt    # database index file.
new_certs_dir   = $dir/nuevoscerts  # default place for new certs.

certificate = $dir/ac1cert.pem  # The CA certificate
serial      = $dir/serial       # The current serial number
crl     = $dir/ca1crl.pem       # The current CRL
private_key = $dir/privado/ca1key.pem # The private key
RANDFILE    = $dir/privado/.rand    # private random number file

x509_extensions = usr_cert      # The extentions to add to the cert

name_opt    = ca_default        # Subject Name options
cert_opt    = ca_default        # Certificate field options

default_days    = 365           # how long to certify for
default_crl_days= 7         # how long before next CRL
default_md  = sha256            # which md to use.
preserve    = no            # keep passed DN ordering

policy      = policy_match

# For the CA policy
[ policy_match ]
countryName     = optional
stateOrProvinceName = optional 
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

####################################################################
[ req ]
default_bits        = 2048
default_keyfile     = ./AC1/privado/ca1key.pem
default_md      = sha256
prompt          = no 
distinguished_name  = req_distinguished_name
attributes      = req_attributes
x509_extensions     = v3_ca # The extentions to add to the self signed cert

string_mask = nombstr

[ req_distinguished_name ]
countryName         = ES
stateOrProvinceName     = MADRID
organizationName        = UC3M
organizationalUnitName      = INF
commonName          = AC1-{ID_ALUMNO}
emailAddress            = AC1@SPI.INF.UC3M.ES

[ req_attributes ]
challengePassword       = A challenge password
challengePassword_min       = 4
challengePassword_max       = 20
unstructuredName        = An optional company name

[ usr_cert ]
basicConstraints=CA:FALSE
nsComment           = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign

[ v3_subca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign
subjectAltName=email:copy

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always
"""
	# Escribimos el archivo quitando espacios sobrantes al inicio y final
    with open(CNF_PATH, "w") as f:
        f.write(contenido_cnf.strip())
    logging.info("Archivo %s creado automáticamente.", CNF_PATH)
          
def inicializar_estructura_ac1(ac1_password):
    crear_archivo_configuracion_si_no_existe()
    
    dirs = ["AC1", "AC1/solicitudes", "AC1/crls", "AC1/nuevoscerts", "AC1/privado"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    
    if not os.path.exists("AC1/index.txt"):
        with open("AC1/index.txt", "w") as f: pass
    
    if not os.path.exists("AC1/serial"):
        with open("AC1/serial", "w") as f: f.write("01\n")

    if not os.path.exists("AC1/privado/ca1key.pem"):
        logging.info("Generando AC1 mediante OpenSSL...")
        # Generar Clave Privada de AC1
        subprocess.run([
            "openssl", "genrsa", "-aes256", 
            "-passout", f"pass:{ac1_password}",
            "-out", "AC1/privado/ca1key.pem", "4096"
        ], check=True)

		# Generar Certificado Autofirmado
        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-key", "AC1/privado/ca1key.pem",
            "-passin", f"pass:{ac1_password}",
            "-out", AC1_CERT_PATH,
            "-days", "3650",
            "-config", CNF_PATH
        ], check=True)
        logging.info("Certificado AC1 generado correctamente")

def firmar_csr_con_openssl(ruta_csr, ruta_cert_destino, ac1_password):
    """Firma una CSR usando OpenSSL y la CA1 configurada"""
    logging.info("Firmando %s con política OpenSSL...", ruta_csr)
    
    cmd = [
        "openssl", "ca",
        "-config", CNF_PATH,
        "-in", ruta_csr,
        "-out", ruta_cert_destino,
        "-extensions", "usr_cert",
        "-batch", 
        "-passin", f"pass:{ac1_password}"
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        logging.info("Firma OK. Certificado en %s", ruta_cert_destino)
        return True
    except subprocess.CalledProcessError as e:
        logging.error("Error al firmar con OpenSSL:\n%s", e.stderr.decode())
        print("Error crítico al firmar el certificado. Revisa los logs.")
        return False
