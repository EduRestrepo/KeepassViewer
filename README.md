# KeePass Web Viewer v2.0

Visualizador web moderno y seguro para archivos de base de datos KeePass (.kdbx), diseñado para equipos de tecnología con integración de Active Directory y SharePoint.

## 🚀 Características
- **Autenticación AD/LDAP**: Validación de usuarios y grupos contra Active Directory (NTLM).
- **Integración SharePoint**: Sincronización en tiempo real mediante volúmenes de Docker y OneDrive.
- **Seguridad**: Soporte para algoritmos legacy (NTLM/MD4) mediante configuración de OpenSSL.
- **Diseño Premium**: Interfaz responsive con modo oscuro y estética "Glassmorphism".
- **Easter Egg**: Presiona 7 veces el título principal para activar el modo "HACKED".

## 🛠️ Configuración de SharePoint
Para utilizar una base de datos alojada en SharePoint:

1. **Sincroniza** la carpeta de SharePoint en tu máquina host usando OneDrive.
2. Abre el archivo `docker-compose.yml` y localiza la sección de `volumes`.
3. Mapea la ruta local de tu Windows a la ruta interna del contenedor:
   ```yaml
   volumes:
     - "C:\\Tu\\Ruta\\Sincronizada\\archivo.kdbx:/app/data/kpsisdb.kdbx"
   ```
4. En el panel de configuración de la Web, asegúrate de que la ruta sea `/app/data/kpsisdb.kdbx`.

## 📂 Estructura del Proyecto
- `/backend`: Servidor FastAPI (Python) con lógica de desencriptación y autenticación.
- `/frontend`: Interfaz de usuario (HTML/JS/CSS).
- `/data`: Directorio local para persistencia (si no se usa SharePoint).

## 🔑 Autenticación AD (PEREZ-LLORCA.NET)
La aplicación está pre-configurada para el dominio `PEREZ-LLORCA.NET`. 
- **Servidor**: `192.168.1.190`
- **Puerto**: `389` (LDAP estándar)
- **Grupo Requerido**: `Admins. del dominio`

## 🌉 Puente de Autenticación Local (Auth Bridge)
Debido a que las políticas de seguridad (GPO) de `PEREZ-LLORCA.NET` bloquean los Binds simples de LDAP y NTLM para cuentas altamente privilegiadas (como las del grupo `Admins. del dominio`), se ha implementado un **puente de autenticación nativo** en el servidor host:

1. El backend del contenedor Docker se conecta al host usando el DNS interno `host.docker.internal:8888`.
2. El script nativo del host valida las credenciales a través del canal de seguridad integrado de Windows (usando Kerberos/Negotiate en segundo plano bajo tu sesión activa).
3. Si la autenticación es correcta, devuelve de forma segura la pertenencia a los grupos del AD al contenedor.

### Gestión del Puente (Servidor Windows Host)
Los scripts de control están ubicados en la carpeta `/scratch`:
- **`scratch/auth_helper.py`**: El servidor HTTP puente en Python nativo.
- **`scratch/start_auth_bridge.bat`**: Script ejecutable de Windows para arrancar el puente de autenticación en modo invisible (`Hidden`). Simplemente haz doble clic sobre él en el servidor si este se reinicia.
- El puente ya está configurado y ejecutándose en el puerto `8888`.

## 🐳 Despliegue con Docker
```bash
# Iniciar la aplicación
docker compose up -d --build

# Reiniciar tras cambios en la configuración del volumen
docker compose restart
```

---
*Desarrollado por Eduardo Restrepo | v2.0*
