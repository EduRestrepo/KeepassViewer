# KeePass Web Viewer & Manager v1.2 Beta
> **By Eduardo Restrepo**

Una solución moderna, segura y profesional para el acceso compartido a archivos KeePass (`.kdbx`) dentro del equipo de tecnología.

## 🚀 Novedades de la Versión 1.2 Beta
- **Seguridad Reforzada (JWT)**: Implementación de JSON Web Tokens para una gestión de sesiones más robusta y segura.
- **Cifrado de Configuración**: Las credenciales sensibles del servidor ahora se almacenan cifradas en disco.
- **Navegación Jerárquica**: Nuevo sistema de árbol de grupos dinámico para una mejor organización de las credenciales.
- **Utilidades de Password**: Generador de claves aleatorias y medidor de fuerza de seguridad integrados.
- **Copiado Rápido**: Botones dedicados para copiar usuario y contraseña directamente desde la tabla principal.
- **Iconos Nativos**: Integración de Lucide Icons para una interfaz más intuitiva y profesional.
- **Soporte Multiusuario Concurrente**: Optimización para que múltiples personas trabajen simultáneamente sobre el mismo archivo sin conflictos.

## 🛠️ Características Principales
- **Interfaz Ultra-Premium**: Diseño oscuro con efectos avanzados de glassmorphism y animaciones fluidas.
- **Autenticación AD/LDAP**: Integración directa con el Directorio Activo para el acceso corporativo.
- **Sincronización en Tiempo Real**: Cambios instantáneos vía WebSockets (Socket.io).
- **Gestión Completa (CRUD)**: Control total sobre entradas y grupos.
- **Panel de Administración**: Configuración centralizada y segura.

## 📁 Estructura del Proyecto
- `backend/`: API REST con FastAPI + Socket.io + Lógica de cifrado.
- `frontend/`: Single Page Application (SPA) moderna con CSS/JS puro.
- `data/`: Directorio seguro para el archivo de base de datos.
- `scripts/`: Herramientas de mantenimiento y automatización.

## 🔐 Credenciales por Defecto (Entorno de Desarrollo)
- **Admin**: `admin` / `admin`
- **KeePass Maestro (Demo)**: `master`
- **LDAP Mock**: `tech_user1` / `password`

## 🐳 Despliegue con Docker (Recomendado)
Para una ejecución rápida y aislada:

1. **Construir e iniciar**:
   ```powershell
   docker-compose up -d --build
   ```

## 🚩 Primeros Pasos (Configuración Inicial)
**IMPORTANTE**: Al iniciar el sistema por primera vez, debes seguir estos pasos para que la aplicación funcione correctamente:

1. **Acceso Inicial**: Entra en `http://localhost:3007` e inicia sesión con las credenciales por defecto:
   - **Usuario**: `admin`
   - **Contraseña**: `admin`
2. **Configuración del Entorno**: Una vez dentro, haz clic en el icono de **Configuración** (esquina superior derecha) para ajustar los siguientes parámetros:
   - **Usuario Administrador**: Cambia la contraseña por defecto por una segura.
   - **Ubicación del Archivo**: Asegúrate de que apunte a `/app/data/nombre_de_tu_archivo.kdbx`.
   - **Active Directory (LDAP)**: Configura el servidor, dominio y el **Grupo de Autenticación** requerido para tus usuarios.
   - **Backup**: Utiliza el botón **"Exportar Backup"** para obtener copias de seguridad de tu archivo `.kdbx` en cualquier momento.
3. **Persistencia**: 
   - El archivo físico `.kdbx` debe estar en la carpeta raíz `./data/` de este proyecto en tu Windows.
   - La configuración se guarda automáticamente en `./backend/config.json`.

## 🏁 Inicio Manual
El servidor se sirve por defecto en `http://localhost:3007`.

Para iniciar el entorno manualmente:
```powershell
cd backend
python main.py
```

---
*Este proyecto es parte del ecosistema de herramientas internas del equipo de tecnología.*
