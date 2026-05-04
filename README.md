# KeePass Web Viewer & Manager

Una solución moderna y segura para el acceso compartido a archivos KeePass dentro del equipo de tecnología.

## Características
- **Interfaz Premium**: Diseño oscuro con efectos de glassmorphism y animaciones fluidas.
- **Autenticación AD**: Soporte para autenticación con el Directorio Activo (LDAP).
- **Sincronización en Tiempo Real**: Los cambios realizados por un usuario se reflejan instantáneamente en todos los demás sin necesidad de recargar.
- **Gestión Completa (CRUD)**: Visualizar, crear, editar y eliminar entradas.
- **Panel de Administración**: Configuración segura de la ruta del archivo y parámetros de red.

## Estructura del Proyecto
- `backend/`: Servidor FastAPI + Socket.io + Lógica de KeePass.
- `frontend/`: Aplicación web moderna (HTML/CSS/JS).
- `data/`: Almacenamiento del archivo `.kdbx`.
- `scripts/`: Utilidades para mantenimiento.

## Credenciales por Defecto
- **Admin**: `admin` / `admin`
- **KeePass Maestro (Sample)**: `master`
- **Usuarios Tech (Mock)**: `tech_user1` / cualquier pass

## Ejecución
El servidor ya se encuentra en ejecución en `http://localhost:3007`.

Para iniciar manualmente en el futuro:
```powershell
cd backend
python main.py
```
