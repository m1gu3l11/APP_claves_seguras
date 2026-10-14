# Aplicación de intercambio seguro de archivos

Proyecto académico colaborativo de seguridad informática centrado en la aplicación de técnicas criptográficas para proteger el intercambio de archivos entre usuarios. El proyecto combina criptografía simétrica y asimétrica, certificados digitales, firmas digitales y autenticación de usuarios.

## Características principales

- **Autenticación de usuarios:** almacenamiento de contraseñas mediante hashes derivados con Scrypt y generación de claves criptográficas individuales.
- **Infraestructura de clave pública (PKI):** configuración de una autoridad certificadora (AC1) mediante OpenSSL y gestión de certificados digitales X.509 para los usuarios.
- **Cifrado híbrido:** protección de archivos mediante AES-256-GCM y cifrado de la clave simétrica con RSA-OAEP y SHA-256.
- **Firmas digitales:** generación y verificación de firmas RSA-PSS con SHA-256 para comprobar la integridad de los archivos y la autenticidad del emisor.
- **Gestión de claves:** generación de pares de claves RSA y protección de las claves privadas mediante contraseña.
- **Gestión de certificados:** creación de solicitudes de firma de certificados (CSR), emisión de certificados y verificación de su firma por la autoridad certificadora.

## Tecnologías utilizadas

- **Python:** implementación de la lógica criptográfica y gestión de usuarios.
- **cryptography:** operaciones criptográficas, generación de claves, cifrado, descifrado y firmas digitales.
- **OpenSSL:** creación de la autoridad certificadora y emisión de certificados.
- **SQLite:** almacenamiento de los usuarios y las rutas asociadas a sus claves y certificados.
- **Tkinter:** interfaz gráfica para interactuar con las funcionalidades de la aplicación.

## Arquitectura del proyecto

| Archivo | Descripción |
| --- | --- |
| `pratica.py` | Implementación de la lógica criptográfica, autenticación, gestión de claves, cifrado híbrido y firmas digitales. |
| `ac1_manager.py` | Inicialización de la autoridad certificadora AC1 y firma de solicitudes de certificados mediante OpenSSL. |
| `app.py` | Interfaz gráfica para interactuar con las funcionalidades del sistema. |
| `requirements.txt` | Dependencias de Python necesarias para ejecutar el proyecto. |

## Funcionamiento del cifrado híbrido

El intercambio seguro de archivos se basa en la combinación de criptografía simétrica y asimétrica:

1. El emisor selecciona un destinatario registrado y un archivo.
2. Se genera una clave simétrica temporal AES de 256 bits, utilizada para cifrar el archivo mediante AES-GCM.
3. La clave simétrica se cifra con la clave pública RSA del destinatario utilizando RSA-OAEP con SHA-256.
4. El contenido cifrado y la clave simétrica protegida se guardan en un sobre digital.
5. El emisor genera una firma digital del archivo original mediante RSA-PSS con SHA-256.
6. El destinatario utiliza su clave privada para recuperar la clave simétrica y descifrar el archivo.
7. Se verifica la firma digital utilizando la clave pública asociada al certificado del emisor, comprobando la integridad del archivo y la autenticidad de la firma.

## Gestión de certificados digitales

La aplicación utiliza una autoridad certificadora propia, denominada AC1, para gestionar los certificados de los usuarios.

El proceso contempla:

- Generación de pares de claves RSA individuales.
- Creación de solicitudes de firma de certificados (CSR).
- Emisión de certificados X.509 mediante OpenSSL.
- Verificación de que los certificados de usuario han sido firmados por la autoridad certificadora.
- Gestión de la estructura de archivos y registros necesarios para la administración de la autoridad certificadora.

## Instalación y ejecución

### Requisitos previos

- Python 3.
- OpenSSL instalado y disponible desde la terminal.
- Las dependencias especificadas en `requirements.txt`.

Clona el repositorio y accede a su directorio:

```bash
git clone <URL_DEL_REPOSITORIO>
cd <DIRECTORIO_DEL_PROYECTO>
```

Crea y activa un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

En Windows, activa el entorno mediante:

```powershell
.venv\Scripts\Activate.ps1
```

Instala las dependencias:

```bash
pip install -r requirements.txt
```

Comprueba que OpenSSL está disponible:

```bash
openssl version
```

Inicia la aplicación:

```bash
python app.py
```

La primera ejecución requiere inicializar la autoridad certificadora. Para ello, se debe establecer una contraseña maestra segura que proteja su clave privada.

## Aprendizajes

Este proyecto permitió aplicar conceptos de criptografía simétrica y asimétrica, infraestructura de clave pública (PKI), certificados digitales, firmas digitales, gestión segura de claves y autenticación de usuarios, así como integrar estos mecanismos en una aplicación de escritorio.
