from fastapi import FastAPI, HTTPException, status, File, UploadFile, Form, Path, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel
from datetime import date, time
from typing import Optional, List
import mysql.connector
import jwt
import datetime
from ftplib import FTP
from config import db_config, ftp_config

# Librerias para imagenes
from PIL import Image
import shutil

# Librerias para hashing y slat de contraseñas
import hashlib
import base64
import os

# Libreria para obterner la direccion
from geopy.geocoders import Nominatim



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def ftp_connect():
    ftp = FTP()
    ftp.connect(ftp_config['host'], ftp_config['port'])
    ftp.login(ftp_config['user'], ftp_config['passwd'])
    return ftp

# Modelo de datos
class Usuario(BaseModel):
    nombre: str
    contrasena: str
    area: str
    estado: int
    permisos: int
    # salt: Optional[str] = None

class Credenciales(BaseModel):
    nombre: str
    contrasena: str

class Carrusel(BaseModel):
    estado: int
    url: str

class Ubicaciones(BaseModel):
    latitud: float
    longitud: float
    lugar: str

class Contacto(BaseModel):
    nombre_institucion: str
    direccion: str
    telefono: str
    email: str
    horario: str
    facebook: str
    x: str
    youtube: str

class Bot(BaseModel):
    nombre: str
    correo: str
    problema: str
    area: str

class Encuestas(BaseModel):
    titulo: str

class Preguntas(BaseModel):
    id_encuesta: int
    pregunta: str
    tipo: str


class Opciones(BaseModel):
    id_pregunta: int
    id_encuesta: int
    opcion: str

class EditarOpcion(BaseModel):
    opcion: str

class Respuesta_abierta(BaseModel):
    id_pregunta:int
    id_encuesta: int
    respuesta: str

class Editar_respuesta_abierta(BaseModel):
    respuesta: str

class Respuesta_cerrada(BaseModel):
    id_opcion: int
    id_pregunta:int
    id_encuesta: int

class Editar_respuesta_cerrada(BaseModel):
    id_opcion: int

class Articulo(BaseModel):
    num_articulo: int

class Fraccion(BaseModel):
    fraccion: str
    descripcion: str
    num_articulo: int
    areas: list[int]  # Lista de ids de áreas

class Año(BaseModel):
    año: int
    id_fraccion: int

class Trimestre(BaseModel):
    trimestre: int
    id_año: int

class Documento(BaseModel):
    id_trimestre: int
    documento: str

class Tramite(BaseModel):
    nombre: str

class Requisito(BaseModel):
    requisito: str
    id_tramite: int

class Editar_requisito(BaseModel):
    requisito: str

class Color(BaseModel):
    nombre_color: str
    valor_hex: str

class Buzon(BaseModel):
    nombre: str
    telefono: str
    correo: str
    comentarios: str 

class Tomo(BaseModel):
    nombre_tomo: str
    descripcion: str 

class Seccion(BaseModel):
    nombre_seccion: str

class FraccionConac(BaseModel):
    nombre_fraccion: str

class Explora (BaseModel):
    nombre_lugar: str
    direccion: str
    descripcion: str

app.mount("/static", StaticFiles(directory="static"),name="static")

geolocator = Nominatim(user_agent="my-unique-application")

def create_ftp_directory(ftp, path):
    # Divide el path en sus componentes y crea cada uno si no existe
    dirs = path.split("/")
    path = ""
    for dir in dirs:
        if dir:
            path += f"/{dir}"
            try:
                ftp.mkd(path)
            except Exception as e:
                # Si el directorio ya existe, no hacer nada
                pass

# Endpoint raiz
@app.get("/", status_code=status.HTTP_200_OK, summary="Endpoint raiz", tags=['Root'])
def root():
    return {'root'}

# funciones extra
def generar_contrasena_salt (contrasena):

    # Salt de 16 bytes (128 bits)
    salt = os.urandom(16)  
    # Salt en Base64 para guardar en la base de datos
    salt_base64 = base64.b64encode(salt).decode('utf-8')

    # Concatenar el salt con la contraseña original
    contrasena_con_salt = salt + contrasena.encode('utf-8')
    # Crear un hash SHA-256 de la contraseña con salt
    sha256_hash = hashlib.sha256(contrasena_con_salt).digest()
    # Codificar el hash resultante en Base64
    contrasena_hashed_base64 = base64.b64encode(sha256_hash).decode('utf-8')
    
    return (contrasena_hashed_base64,salt_base64)

# Función para verificar las credenciales
def verificar_credenciales(nombre: str, contrasena: str):
    # Clave secreta para firmar los tokens JWT
    SECRET_KEY = "MEXICO_0-4_URUGUAY" # MAFUFADA DE SELECCION

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT contrasena, salt, permisos, estado, area FROM usuarios WHERE nombre = %s;"
        cursor.execute(query, (nombre,))
        usuario = cursor.fetchone()

        if usuario:
            contrasena_db, salt_base64 = usuario[0], usuario[1]
            salt_original = base64.b64decode(salt_base64.encode('utf-8'))

            # Generar hash SHA-256 de la contraseña proporcionada con el salt de la base de datos
            contrasena_con_salt = salt_original + contrasena.encode('utf-8')
            sha256_hash = hashlib.sha256(contrasena_con_salt).digest()
            contrasena_hashed = base64.b64encode(sha256_hash).decode('utf-8')

            if contrasena_hashed == contrasena_db:
                estado = usuario[3]
                if estado == '0':
                    return {"mensaje": "Usuario no activo"}
                else:
                    nivel_permiso = usuario[2]
                    area = usuario[4]
                    if nivel_permiso == '0':
                        rol = 'director transparencia'
                    elif nivel_permiso == '1':
                        rol = 'administrador'
                    else:
                        rol = 'director area'
                    
                    # Generar el token JWT
                    token = jwt.encode({
                        'nombre': nombre,
                        'rol': rol,
                        'area': area,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                    }, SECRET_KEY, algorithm='HS256')

                    return {"mensaje": "Credenciales correctas", "rol": rol, "area": area, "token": token}
            else:
                return {"mensaje": "Credenciales incorrectas"}
        else:
            return {"mensaje": "Credenciales incorrectas"}
    except mysql.connector.Error as err:
        print(f"Error al verificar credenciales en la base de datos: {err}")
        return {"mensaje": "Error al verificar credenciales en la base de datos"}
    finally:
        cursor.close()
        connection.close()

# Endpoint para iniciar sesión
@app.post("/login", status_code=status.HTTP_200_OK, summary="Endpoint para iniciar sesión", tags=['Login'])
def iniciar_sesion(credenciales: Credenciales):
    resultado_verificacion = verificar_credenciales(credenciales.nombre, credenciales.contrasena)

    if resultado_verificacion["mensaje"] == "Credenciales correctas":
        return {
            "mensaje": "Sesión iniciada",
            "rol": resultado_verificacion["rol"],
            "area": resultado_verificacion["area"],
            "token": resultado_verificacion["token"]
        }
    elif resultado_verificacion["mensaje"] == "Usuario no activo":
        raise HTTPException(status_code=403, detail="Usuario no activo")
    else:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

# Listar todos los usuarios (sin la contraseña)
@app.get("/usuario", status_code=status.HTTP_200_OK, summary="Endpoint para listar datos de usuarios", tags=['Usuario'])
def listar_usuarios():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT id_usuario, nombre, area, estado, permisos FROM usuarios")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id': row[0],
                    'nombre': row[1],
                    'area':row[2],
                    'estado': row[3],
                    'permisos': row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay usuarios en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Detalle de un usuario
@app.get("/usuario/{id_usuario}",status_code=status.HTTP_200_OK, summary="Endpoint para listar un solo usuario", tags=['Usuario'])
def detalle_usuario(id_usuario: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM usuarios WHERE id_usuario = %s;"
        cursor.execute(query, (id_usuario,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id': row[0],
                    'nombre': row[1],
                    'contrasena':row[2],
                    'area': row[3],
                    'estado': row[4],
                    'permisos': row[5]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    finally:
        cursor.close()
        connection.close()

# Crear un usuario
@app.post("/usuario/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un nuevo usuario", tags=['Usuario'])
def crear_usuario(usuario: Usuario):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Validar valores de estado y permisos
        if usuario.estado not in [0, 1]:
            raise HTTPException(status_code=400, detail="El valor de 'estado' debe ser '0', '1'")
        if usuario.permisos not in [0, 1, 2]:
            raise HTTPException(status_code=400, detail="El valor de 'permisos' debe ser '0', '1' o '2'")
        
        usuario.estado = str(usuario.estado) # Convertimos a str el estado y permisos para que no tome como posicion el valor
        usuario.permisos = str(usuario.permisos) # si no como el valor representado}

        contrasena_hashed , salt = generar_contrasena_salt(usuario.contrasena)

        # Insertar nuevo usuario en la base de datos
        query = "INSERT INTO usuarios (nombre, contrasena, area, estado, permisos, salt) VALUES (%s, %s, %s, %s, %s,%s)"
        usuario_data = (usuario.nombre, contrasena_hashed, usuario.area, usuario.estado, usuario.permisos, salt)
        cursor.execute(query, usuario_data)
        connection.commit()

        return {
            "nombre":usuario.nombre,
            "area": usuario.area,
            "estado":usuario.estado,
            "permisos":usuario.permisos,
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar usuario en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear usuario")
    finally:
        cursor.close()
        connection.close()

# Editar un usuario
@app.put("/usuario/editar/{id_usuario}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un usuario existente", tags=['Usuario'])
def editar_usuario(id_usuario: int, usuario: Usuario):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Validar valores de estado y permisos
        if usuario.estado not in [0, 1]:
            raise HTTPException(status_code=400, detail="El valor de 'estado' debe ser '0' o '1'")
        if usuario.permisos not in [0, 1, 2]:
            raise HTTPException(status_code=400, detail="El valor de 'permisos' debe ser '0', '1' o '2'")
        
        usuario.estado = str(usuario.estado) # Convertimos a str el estado y permisos para que no tome como posicion el valor
        usuario.permisos = str(usuario.permisos) # si no como el valor representado

        # Obtener la contraseña y el salt actuales de la base de datos
        cursor.execute("SELECT contrasena, salt FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        resultado = cursor.fetchone()
        if not resultado:
            raise HTTPException(status_code=404, detail=f"Usuario con id {id_usuario} no encontrado")
        
        contrasena_actual_hashed, salt_actual = resultado

        # Verificar si la contraseña proporcionada es la misma que la almacenada
        if usuario.contrasena == contrasena_actual_hashed:
            contrasena_hashed, salt = contrasena_actual_hashed, salt_actual
        else:
            contrasena_hashed, salt = generar_contrasena_salt(usuario.contrasena)

        # Actualizar usuario en la base de datos
        query = """
            UPDATE usuarios
            SET nombre = %s, contrasena = %s, area = %s, estado = %s, permisos = %s , salt = %s
            WHERE id_usuario = %s
        """
        usuario_data = (usuario.nombre, contrasena_hashed, usuario.area, usuario.estado, usuario.permisos, salt, id_usuario)
        cursor.execute(query, usuario_data)
        connection.commit()

        return {"mensaje": f"Usuario con id {id_usuario} actualizado correctamente"}
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar usuario en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al editar usuario")
    finally:
        cursor.close()
        connection.close()

# Detalle de un usuario
@app.delete("/usuario/borrar/{id_usuario}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un usuario", tags=['Usuario'])
def borrar_usuario(id_usuario: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "DELETE FROM usuarios WHERE id_usuario = %s;"
        cursor.execute(query, (id_usuario,))
        connection.commit() 

        if cursor.rowcount > 0:
            return {"mensaje": f"Usuario con id {id_usuario} eliminado correctamente"}
        else:
            raise HTTPException(status_code=404, detail=f"Usuario con id {id_usuario} no encontrado")
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al borrar usuario en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar usuario")
    finally:
        cursor.close()
        connection.close()

@app.get("/logo",status_code=status.HTTP_200_OK, summary="Endpoint para listar el logo activo de la pagina", tags=['Logo'])
def listar_logo():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM logo")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'archivo': row[1],
                    'ruta': row[2]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No un logo en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/logo/subir", status_code=status.HTTP_200_OK, summary="Endpoint para subir un logo a la página", tags=['Logo'])
async def subir_logo(file: UploadFile = File(...)):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Comprobar la extensión del archivo
        if not file.filename.lower().endswith(".png"):
            raise HTTPException(status_code=400, detail="Solo se permiten archivos con extensión .png")

        # Guardar temporalmente el archivo
        temp_file_location = f"static/temp/{file.filename}"
        with open(temp_file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Abrir la imagen y comprobar el tamaño
        with Image.open(temp_file_location) as img:
            if img.size < (200, 200):
                raise HTTPException(status_code=400, detail="El logo tiene que ser mayor a 200x200")
            elif img.size > (9000, 9000):
                raise HTTPException(status_code=400, detail="El logo tiene que ser menor a 9000x9000")

        # Configurar la conexión FTP usando la función ftp_connect
        with ftp_connect() as ftp:
            ftp_path = f"/static/images/logos"
            create_ftp_directory(ftp, ftp_path)
            ftp_file_location = f"{ftp_path}/{file.filename}"

            # Subir el archivo al servidor FTP
            with open(temp_file_location, "rb") as f:
                ftp.storbinary(f"STOR {ftp_file_location}", f)

            # Generar la URL pública del archivo
            base_url = "https://test.santiagotulantepec.com"
            file_url = f"{base_url}{ftp_file_location}"

        # Mover el archivo temporal al directorio final si pasa las validaciones
        final_location = f"static/images/logos/{file.filename}"
        shutil.move(temp_file_location, final_location)

        # Actualizar la base de datos con la nueva ubicación del logo
        update_query = "UPDATE logo SET imagen = %s, ruta = %s WHERE id_logo = 1"
        cursor.execute(update_query, (file.filename, file_url))
        connection.commit()

        return JSONResponse(content={"filename": file.filename})

    except mysql.connector.Error as err:
        print(f"Error MySQL al subir el logo: {err}")
        raise HTTPException(status_code=500, detail="Error interno al subir logo")

    except Exception as e:
        print(f"Error al subir el logo: {e}")
        raise HTTPException(status_code=500, detail="Error interno al subir logo")

    finally:
        cursor.close()
        connection.close()
@app.post("/logo/borrar", status_code=status.HTTP_200_OK, summary="Endpoint para borrar el logo actual", tags=['Logo'])
async def borrar_logo():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Obtener el nombre del archivo actual desde la base de datos
        cursor.execute("SELECT imagen FROM logo WHERE id_logo = 1")
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="Logo no encontrado")

        current_filename = result[0]
        default_filename = "default_icon.png"
        default_path = "static/images/logos/"

        # Configurar la conexión FTP usando la función ftp_connect
        with ftp_connect() as ftp:
            # Eliminar el archivo del servidor FTP si no es el archivo por defecto
            if current_filename != default_filename:
                ftp_file_path = f"{default_path}/{current_filename}"
                try:
                    ftp.delete(ftp_file_path)
                except Exception as e:
                    print(f"Error al eliminar el archivo del FTP: {e}")

        # Actualizar la base de datos con el nombre del archivo por defecto
        update_query = """
            UPDATE logo
            SET imagen = %s, ruta = %s
            WHERE id_logo = 1
        """
        cursor.execute(update_query, (default_filename, default_path))
        connection.commit()

        return JSONResponse(content={"message": "Logo borrado y reemplazado por el ícono por defecto"})

    except mysql.connector.Error as err:
        print(f"Error MySQL al borrar el logo: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar logo")

    except Exception as e:
        print(f"Error al borrar el logo: {e}")
        raise HTTPException(status_code=500, detail="Error interno al borrar logo")

    finally:
        cursor.close()
        connection.close()

@app.get("/avisos",status_code=status.HTTP_200_OK, summary="Endpoint para listar los avisos de la pagina", tags=['Carrusel'])
def listar_avisos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM carrusel")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_aviso':row[0],
                    'imagen': row[1],
                    'ruta': row[2],
                    'estado': row[3],
                    'url': row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay avisos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/avisos/activos",status_code=status.HTTP_200_OK, summary="Endpoint para listar los avisos de la pagina", tags=['Carrusel'])
def listar_avisos_activos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM carrusel WHERE estado ='1'")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_aviso':row[0],
                    'imagen': row[1],
                    'ruta': row[2],
                    'estado': row[3],
                    'url': row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay avisos activos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/aviso/{id_aviso}",status_code=status.HTTP_200_OK, summary="Endpoint para listar un aviso del carrusel de la pagina", tags=['Carrusel'])
def detalle_aviso(id_aviso:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM carrusel WHERE id_imagen= %s"
        cursor.execute(query, (id_aviso,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_aviso':row[0],
                    'imagen': row[1],
                    'ruta': row[2],
                    'estado': row[3],
                    'url': row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe ese aviso en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/aviso/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un aviso y que se vea reflejado en el carrusel de imágenes", tags=['Carrusel'])
async def crear_aviso(
    estado: int = Form(...),
    url: str = Form(...),
    file: UploadFile = File(...)
):
    # Validar valores de estado
    if estado not in [0, 1]:
        raise HTTPException(status_code=400, detail="El valor de 'estado' debe ser '0' o '1'")
        
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Guardar temporalmente el archivo
        file_location = f"static/temp/{file.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Abrir la imagen y comprobar el tamaño
        with Image.open(file_location) as img:
            if img.size < (200, 200):
                raise HTTPException(status_code=400, detail="La imagen debe ser mayor a 200x200 píxeles")
            elif img.size > (30000, 30000):
                raise HTTPException(status_code=400, detail="La imagen debe ser menor a 9000x9000 píxeles")

        # Mover el archivo al directorio final si pasa las validaciones
        final_location = f"static/images/carrusel/{file.filename}"
        shutil.move(file_location, final_location)

        # Subir el archivo al servidor FTP con la ruta completa
        ftp_path = "/static/images/carrusel"
        with ftp_connect() as ftp:
            create_ftp_directory(ftp, ftp_path)
            file_full_path = f"{ftp_path}/{file.filename}"
            with open(final_location, 'rb') as f:
                ftp.storbinary(f"STOR {file_full_path}", f)

        # Generar la URL pública del archivo
        base_url = "https://test.santiagotulantepec.com"
        file_url = f"{base_url}{file_full_path}"

        # Insertar datos en la base de datos incluyendo la URL del archivo
        insert_query = 'INSERT INTO carrusel (imagen, ruta, estado, url) VALUES (%s, %s, %s, %s)'
        data = (file.filename, file_url, estado, url)
        cursor.execute(insert_query, data)
        connection.commit()

        # Formato de respuesta
        response_data = {
            "id_aviso": cursor.lastrowid,  # Obtener el ID del último aviso insertado
            "imagen": file.filename,
            "ruta": file_url,
            "estado": str(estado),
            "url": url
        }
        return JSONResponse(content=response_data)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

    finally:
        cursor.close()
        connection.close()

@app.put("/aviso/editar/{id_aviso}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un aviso existente en el carrusel de imágenes", tags=['Carrusel'])
async def editar_aviso(
    id_aviso: int,
    estado: int = Form(...),
    url: str = Form(...),
    file: UploadFile = File(None)  # Archivo opcional para la edición
):
    if estado not in [0, 1]:
        raise HTTPException(status_code=400, detail="El valor de 'estado' debe ser '0' o '1'")
        
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        if file:
            # Guardar temporalmente el archivo
            file_location = f"static/temp/{file.filename}"
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Abrir la imagen y comprobar el tamaño
            with Image.open(file_location) as img:
                if img.size < (200, 200):
                    raise HTTPException(status_code=400, detail="La imagen debe ser mayor a 200x200 píxeles")
                elif img.size > (9000, 9000):
                    raise HTTPException(status_code=400, detail="La imagen debe ser menor a 9000x9000 píxeles")

            # Mover el archivo al directorio final si pasa las validaciones
            final_location = f"static/images/carrusel/{file.filename}"
            shutil.move(file_location, final_location)

            # Subir el archivo al servidor FTP con la ruta completa
            ftp_path = "/static/images/carrusel"
            with ftp_connect() as ftp:
                create_ftp_directory(ftp, ftp_path)
                file_full_path = f"{ftp_path}/{file.filename}"
                with open(final_location, 'rb') as f:
                    ftp.storbinary(f"STOR {file_full_path}", f)


            # Generar la URL pública del archivo en el servidor FTP
            base_url = "https://test.santiagotulantepec.com"
            file_url = f"{base_url}{file_full_path}"

            # Actualizar los datos en la base de datos incluyendo la URL del archivo
            update_query = 'UPDATE carrusel SET imagen=%s, ruta=%s, estado=%s, url=%s WHERE id_imagen=%s'
            data = (file.filename, file_url, estado, url, id_aviso)
            cursor.execute(update_query, data)
        else:
            # Actualizar los datos en la base de datos sin cambiar la imagen
            update_query = 'UPDATE carrusel SET estado=%s, url=%s WHERE id_imagen=%s'
            data = (estado, url, id_aviso)
            cursor.execute(update_query, data)

        connection.commit()

        # Preparar la respuesta JSON
        response_data = {
            "aviso_id": id_aviso,
            "estado": estado,
            "url": url,
            "filename": file.filename if file else "No se cambió la imagen"
        }
        return JSONResponse(content=response_data)

    except mysql.connector.Error as err:
        print(f"Error MySQL al editar el aviso: {err}")
        raise HTTPException(status_code=500, detail="Error interno al editar aviso")

    except Exception as e:
        print(f"Error al procesar la edición del aviso: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar edición aviso")

    finally:
        cursor.close()
        connection.close()


@app.delete("/aviso/borrar/{id_aviso}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un aviso existente en el carrusel de imágenes", tags=['Carrusel'])
async def borrar_aviso(id_aviso: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Obtener el nombre del archivo y la ruta desde la base de datos
        cursor.execute("SELECT imagen FROM carrusel WHERE id_imagen=%s", (id_aviso,))
        aviso = cursor.fetchone()

        if not aviso:
            raise HTTPException(status_code=404, detail="Aviso no encontrado")

        file_name = aviso[0]
        file_path = f"static/images/carrusel/{file_name}"

        # Conectar al servidor FTP y eliminar el archivo si existe
        with ftp_connect() as ftp:
            if ftp:
                ftp_path = "/static/images/carrusel"
                ftp_file_path = f"{ftp_path}/{file_name}"
                
                # Eliminar el archivo del servidor FTP si existe
                try:
                    ftp.delete(ftp_file_path)
                except Exception as e:
                    print(f"Error al borrar archivo en FTP: {e}")

        # Eliminar el aviso de la base de datos
        cursor.execute("DELETE FROM carrusel WHERE id_imagen=%s", (id_aviso,))
        connection.commit()

        # Eliminar el archivo localmente si existe
        if os.path.exists(file_path):
            os.remove(file_path)

        return JSONResponse(content={"message": "Aviso borrado correctamente", "aviso_id": id_aviso})

    except mysql.connector.Error as err:
        print(f"Error MySQL al borrar el aviso: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar aviso")

    except Exception as e:
        print(f"Error al procesar la solicitud de borrado del aviso: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar borrado aviso")

    finally:
        cursor.close()
        connection.close()

@app.get("/ubicacion",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las ubicaciones existentes", tags=['Mapa-Ubicaciones'])
def listar_ubicaciones():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM ubicaciones")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_ubicacion': row[0],
                    'latitud': row[1],
                    'longitud':row[2],
                    'lugar':row[3]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay ubicaciones en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/ubicacion/{id_ubicacion}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una ubicacion en la bd", tags=['Mapa-Ubicaciones'])
def detalle_ubicacion(id_ubicacion:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM ubicaciones WHERE id_ubicacion = %s;"
        cursor.execute(query, (id_ubicacion,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_ubicacion': row[0],
                    'latitud': row[1],
                    'longitud':row[2],
                    'lugar':row[3]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe esa ubicacion en la Base de datos")
    finally:
        cursor.close()
        connection.close()


@app.get("/ubicacion-buscar/{lugar}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una ubicacion en la bd", tags=['Mapa-Ubicaciones'])
def detalle_ubicacion(lugar:str):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM ubicaciones WHERE lugar = %s;"
        cursor.execute(query, (lugar,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_ubicacion': row[0],
                    'latitud': row[1],
                    'longitud':row[2],
                    'lugar':row[3]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe esa ubicacion en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/ubicacion/crear",status_code=status.HTTP_200_OK, summary="Endpoint para crear una ubicacion en el mapa", tags=['Mapa-Ubicaciones'])
def crear_ubicaciones(ubicaciones:Ubicaciones):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar nuevo usuario en la base de datos
        query = "INSERT INTO ubicaciones (latitud, longitud, lugar) VALUES (%s, %s, %s)"
        usuario_data = (ubicaciones.latitud, ubicaciones.longitud, ubicaciones.lugar)
        cursor.execute(query, usuario_data)
        connection.commit()
        return {
            "latitud":ubicaciones.latitud,
            "longitud":ubicaciones.longitud,
            "lugar":ubicaciones.lugar
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar ubicacion en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear ubicacion")
    finally:
        cursor.close()
        connection.close()

@app.put("/ubicacion/editar/{id_ubicacion}",status_code=status.HTTP_200_OK, summary="Endpoint para editar una ubicacion en el mapa", tags=['Mapa-Ubicaciones'])
def editar_ubicacion(ubicaciones:Ubicaciones, id_ubicacion:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar nuevo usuario en la base de datos
        query = 'UPDATE ubicaciones SET latitud=%s, longitud=%s, lugar =%s WHERE id_ubicacion=%s'
        usuario_data = (ubicaciones.latitud, ubicaciones.longitud, ubicaciones.lugar, id_ubicacion)
        cursor.execute(query, usuario_data)
        connection.commit()
        return {
            "latitud":ubicaciones.latitud,
            "longitud":ubicaciones.longitud,
            "lugar":ubicaciones.lugar
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar ubicacion en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar ubicacion")
    finally:
        cursor.close()
        connection.close()



@app.delete("/ubicacion/borrar/{id_ubicacion}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una ubicacion existente en el mapa", tags=['Mapa-Ubicaciones'])
def borrar_ubicacion(id_ubicacion: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si el aviso existe y obtener la información del archivo
    cursor.execute("SELECT * FROM ubicaciones WHERE id_ubicacion=%s", (id_ubicacion,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Ubicacion no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM ubicaciones WHERE id_ubicacion=%s", (id_ubicacion,))
    connection.commit()

    return JSONResponse(content={"message": "Ubicacion borrada correctamente", "id_ubicacion": id_ubicacion})

@app.get("/contacto", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los contactos existentes", tags=['Contactos'])
def listar_contactos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM contactos")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_contacto': row[0],
                    'nombre_institucion': row[1],
                    'direccion': row[2],
                    'telefono': row[3],
                    'email': row[4],
                    'horario': row[5],
                    'facebook': row[6],
                    'x': row[7],
                    'youtube': row[8],
                    'imagen': row[9],
                    'ruta': row[10]
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay contactos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/contacto/{id_contacto}", status_code=status.HTTP_200_OK, summary="Endpoint para buscar una institución en la bd", tags=['Contactos'])
def detalle_contactos(id_contacto: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM contactos WHERE id_contactos = %s"
        cursor.execute(query, (id_contacto,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_contacto': row[0],
                    'nombre_institucion': row[1],
                    'direccion': row[2],
                    'telefono': row[3],
                    'email': row[4],
                    'horario': row[5],
                    'facebook': row[6],
                    'x': row[7],
                    'youtube': row[8],
                    'imagen': row[9],
                    'ruta': row[10]  # Asegúrate de que la columna de la imagen sea la correcta
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe esa institución en la Base de datos")
    finally:
        cursor.close()
        connection.close()


@app.post("/contacto/crear", status_code=status.HTTP_201_CREATED, summary="Endpoint para crear un contacto", tags=['Contactos'])
def crear_contacto(contacto: Contacto):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Si no se proporciona una dirección, buscarla usando el nombre de la institución
        if not contacto.direccion:
            query_ubicacion = "SELECT latitud, longitud FROM ubicaciones WHERE lugar = %s;"
            cursor.execute(query_ubicacion, (contacto.nombre_institucion,))
            datos = cursor.fetchone()
            if datos:
                latitud, longitud = datos
                coordenadas = f"{latitud}, {longitud}"
                location = geolocator.reverse(coordenadas)
                if location:
                    contacto.direccion = location.address
                else:
                    raise HTTPException(status_code=404, detail="No se pudo obtener la dirección a partir de las coordenadas")
            else:
                raise HTTPException(status_code=404, detail="No existe esa ubicación en la Base de datos")

        # Insertar el nuevo contacto en la base de datos
        query = "INSERT INTO contactos (nombre_institucion, direccion, telefono, email, horario, facebook, x, youtube) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        contacto_data = (contacto.nombre_institucion, contacto.direccion, contacto.telefono, contacto.email, contacto.horario, contacto.facebook, contacto.x, contacto.youtube)
        cursor.execute(query, contacto_data)
        connection.commit()
        return contacto
    except mysql.connector.Error as err:
        print(f"Error al insertar contacto en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear contacto")
    finally:
        cursor.close()
        connection.close()


@app.put("/contacto/editar/{id_contacto}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un contacto", tags=['Contactos'])
async def editar_contacto(
    id_contacto: int,
    telefono: str = Form(None),
    email: str = Form(None),
    facebook: str = Form(None),
    x: str = Form(None),
    youtube: str = Form(None),
    imagen: UploadFile = File(None)
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Procesar la imagen si se proporciona
        if imagen:
             # Guardar la imagen en una ubicación temporal
            file_location = f"static/temp/{imagen.filename}"
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(imagen.file, buffer)

            # Mover la imagen a la ubicación final y asegurarse de que sea válida
            final_location = f"static/images/instituciones/{imagen.filename}"
            shutil.move(file_location, final_location)
            
            # Subir la imagen al servidor FTP con la ruta completa
            ftp_path = "/static/images/instituciones"
            with ftp_connect() as ftp:
                create_ftp_directory(ftp, ftp_path)
                with open(final_location, 'rb') as f:
                    ftp.storbinary(f"STOR {ftp_path}/{imagen.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
            base_url = "https://test.santiagotulantepec.com"
            imagen_url = f"{base_url}{ftp_path}/{imagen.filename}"

            # Actualizar la base de datos con la información de la imagen
            query = "UPDATE contactos SET telefono = %s, email = %s, facebook = %s, x = %s, youtube = %s, imagen = %s, ruta = %s WHERE id_contactos = %s"
            contacto_data = (telefono, email, facebook, x, youtube, imagen.filename, imagen_url, id_contacto)
            cursor.execute(query, contacto_data)
            connection.commit()

            return {
                'id_contacto': id_contacto,
                'telefono': telefono,
                'email': email,
                'facebook': facebook,
                'x': x,
                'youtube': youtube,
                'imagen': imagen.filename
            }
        else:
            # Si no se proporciona una imagen, actualizar solo los campos de texto
            query = "UPDATE contactos SET telefono = %s, email = %s, facebook = %s, x = %s, youtube = %s WHERE id_contacto = %s"
            contacto_data = (telefono, email, facebook, x, youtube, id_contacto)
            cursor.execute(query, contacto_data)
            connection.commit()

            return JSONResponse(content={
                'id_contacto': id_contacto,
                'telefono': telefono,
                'email': email,
                'facebook': facebook,
                'x': x,
                'youtube': youtube,
                'imagen': "No se cambió la imagen"
            })
    except mysql.connector.Error as err:
        print(f"Error al actualizar contacto en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar contacto")
    finally:
        cursor.close()
        connection.close()


@app.delete("/contacto/borrar/{id_contacto}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un contacto", tags=['Contactos'])
def borrar_contacto(id_contacto: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si el aviso existe y obtener la información del archivo
    cursor.execute("SELECT * FROM contactos WHERE id_contactos=%s", (id_contacto,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Contacto no encontrado")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM contactos WHERE id_contactos =%s", (id_contacto,))
    connection.commit()

    return JSONResponse(content={"message": "Contacto borrado correctamente", "id_contacto": id_contacto})


@app.get("/noticia",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las noticias existentes", tags=['Noticias'])
def listar_noticias():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM noticias")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_noticia': row[0],
                    'titulo': row[1],
                    'contenido':row[2],
                    'imagen':row[3],
                    'ruta':row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay noticias en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/noticia/{id_noticia}",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las noticias existentes", tags=['Noticias'])
def detalle_noticia(id_noticia:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM noticias WHERE id_noticia = %s"
        cursor.execute(query, (id_noticia,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_titulo': row[0],
                    'titulo': row[1],
                    'contenido':row[2],
                    'imagen':row[3],
                    'ruta':row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay noticias con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/noticia/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una noticia y que se vea reflejado en la seccion de preguntas", tags=['Noticias'])
async def crear_noticia(
    titulo: str = Form(...),
    contenido: str = Form(...),
    file: UploadFile = File(...)
):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Guardar temporalmente el archivo
    file_location = f"static/temp/{file.filename}"
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Abrir la imagen y comprobar el tamaño
    try:
        
        with Image.open(file_location) as img:
            if img.size < (200, 200):
                raise HTTPException(status_code=400, detail="La imagen tiene que ser mayor a 200x200")
            elif img.size > (9000, 9000):
                raise HTTPException(status_code=400, detail="La imagen tiene que ser menor a 9000x9000")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid image file")

    # Mover el archivo al directorio final si pasa las validaciones
    final_location = f"static/images/noticias/{file.filename}"
    shutil.move(file_location, final_location)

    # Subir la imagen al servidor FTP con la ruta completa
    ftp_path = "/static/images/noticias"
    with ftp_connect() as ftp:
        create_ftp_directory(ftp, ftp_path)
        with open(final_location, 'rb') as f:
            ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
    base_url = "https://test.santiagotulantepec.com"
    imagen_url = f"{base_url}{ftp_path}/{file.filename}"

    # Insertar datos en la base de datos
    query = 'INSERT INTO noticias (titulo, contenido, imagen, ruta) VALUES (%s,%s,%s,%s)'
    usuario_data = (titulo, contenido,file.filename, imagen_url)
    cursor.execute(query, usuario_data)
    connection.commit()

    return JSONResponse(content={
        'titulo': titulo,
        'contenido':contenido,
        'imagen': file.filename,
        'ruta': imagen_url
    })
@app.put("/noticia/editar/{id_noticia}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una noticia existente", tags=['Noticias'])
async def editar_noticia(
    id_noticia: int,
    titulo: str = Form(...),
    contenido: str = Form(...),
    file: UploadFile = File(None)  # Archivo opcional para la edición
):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        if file:
            # Guardar temporalmente el archivo
            file_location = f"static/temp/{file.filename}"
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Abrir la imagen y comprobar el tamaño
            try:
                with Image.open(file_location) as img:
                    if img.size < (200, 200):
                        raise HTTPException(status_code=400, detail="La imagen tiene que ser mayor a 200x200")
                    elif img.size > (9000, 9000):
                        raise HTTPException(status_code=400, detail="La imagen tiene que ser menor a 9000x9000")
            except Exception as e:
                raise HTTPException(status_code=400, detail="Archivo de imagen no válido")

            # Mover el archivo al directorio final si pasa las validaciones
            final_location = f"static/images/noticias/{file.filename}"
            shutil.move(file_location, final_location)

            # Subir la imagen al servidor FTP con la ruta completa
            ftp_path = "/static/images/noticias"
            with ftp_connect() as ftp:
                create_ftp_directory(ftp, ftp_path)
                with open(final_location, 'rb') as f:
                    ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
            base_url = "https://test.santiagotulantepec.com"
            imagen_url = f"{base_url}{ftp_path}/{file.filename}"

            # Actualizar los datos en la base de datos
            query = 'UPDATE noticias SET titulo=%s, contenido=%s, imagen=%s, ruta=%s WHERE id_noticia=%s'
            usuario_data = (titulo, contenido, file.filename, imagen_url, id_noticia)
        else:
            # Actualizar los datos en la base de datos sin cambiar la imagen
            query = 'UPDATE noticias SET titulo=%s, contenido=%s WHERE id_noticia=%s'
            usuario_data = (titulo, contenido, id_noticia)

        cursor.execute(query, usuario_data)
        connection.commit()

        return JSONResponse(content={
            "id_noticia": id_noticia,
            "titulo": titulo,
            "contenido": contenido,
            "imagen": file.filename if file else "No se cambió la imagen",
            "ruta": imagen_url if file else "Ruta no cambiada"
        })

    except mysql.connector.Error as err:
        print(f"Error al actualizar noticia en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar noticia")

    except Exception as e:
        print(f"Error al procesar la edición de noticia: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar edición de noticia")

    finally:
        cursor.close()
        connection.close()


@app.delete("/noticia/borrar/{id_noticia}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una noticia existente", tags=['Noticias'])
async def borrar_noticia(id_noticia: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Verificar si la noticia existe y obtener la ruta de la imagen
        cursor.execute("SELECT imagen FROM noticias WHERE id_noticia=%s", (id_noticia,))
        aviso = cursor.fetchone()
        
        if not aviso:
            raise HTTPException(status_code=404, detail="Noticia no encontrada")
        
        # Obtener la ruta completa del archivo
        imagen = aviso[0]

        # Conectar al servidor FTP y eliminar el archivo
        ftp = ftp_connect()
        
        # Construir la ruta completa del archivo en el servidor FTP
        ftp_path = f"/static/images/noticias"
        file_location = f"{ftp_path}/{imagen}"

        # Intentar eliminar el archivo del servidor FTP
        try:
            ftp.delete(file_location)
        except Exception as e:
            print(f"Error al eliminar archivo del servidor FTP: {e}")


        # Eliminar la noticia de la base de datos
        cursor.execute("DELETE FROM noticias WHERE id_noticia=%s", (id_noticia,))
        connection.commit()

        return JSONResponse(content={"message": "Noticia borrada correctamente", "id_noticia": id_noticia})

    except mysql.connector.Error as err:
        print(f"Error al borrar la noticia en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar noticia")
    except Exception as e:
        print(f"Error al procesar la solicitud: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar solicitud")
    finally:
        cursor.close()
        connection.close()

@app.get("/evento",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los eventos existentes", tags=['Eventos'])
def listar_eventos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM eventos")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    "id_evento":row[0],
                    "titulo": row[1],
                    "descripcion":row[2],
                    "fecha":row[3],
                    "hora":row[4],
                    "imagen":row[5],
                    "ruta":row[6]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay eventos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/evento/{id_evento}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar un evento en la bd", tags=['Eventos'])
def detalle_evento(id_evento:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM eventos WHERE id_evento = %s"
        cursor.execute(query, (id_evento,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    "id_evento":row[0],
                    "titulo": row[1],
                    "descripcion":row[2],
                    "fecha":row[3],
                    "hora":row[4],
                    "imagen":row[5],
                    "ruta":row[6]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe ese evento en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/evento/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un evento", tags=['Eventos'])
def crear_evento(
    titulo: str = Form(...),
    descripcion: str = Form(...),
    fecha: date = Form(...),
    hora: time = Form(...),
    file: UploadFile = File(...)):

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    file_location = f"static/temp/{file.filename}"
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        with Image.open(file_location) as img:
            if img.size < (200, 200):
                raise HTTPException(status_code=400, detail="La imagen tiene que ser mayor a 200x200")
            elif img.size > (9000, 9000):
                raise HTTPException(status_code=400, detail="La imagen tiene que ser menor a 9000x9000")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid image file")
    
    final_location = f"static/images/eventos/{file.filename}"
    shutil.move(file_location, final_location)
    
    # Subir la imagen al servidor FTP con la ruta completa
    ftp_path = "/static/images/eventos"
    with ftp_connect() as ftp:
        create_ftp_directory(ftp, ftp_path)
        with open(final_location, 'rb') as f:
            ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
    base_url = "https://test.santiagotulantepec.com"
    imagen_url = f"{base_url}{ftp_path}/{file.filename}"

    query = "INSERT INTO eventos (titulo, descripcion, fecha, hora, imagen, ruta) VALUES (%s, %s, %s, %s, %s, %s)"
    evento_data = (titulo, descripcion, fecha, hora, file.filename, imagen_url)
    cursor.execute(query, evento_data)
    connection.commit()
    return {
        'titulo': titulo,
        'descripcion': descripcion,
        'fecha': fecha,
        'hora': hora,
        'imagen': file.filename,
        'ruta': imagen_url
    }

@app.put("/evento/editar/{id_evento}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un evento", tags=['Eventos'])
def editar_evento(
    id_evento:int, 
    titulo: str = Form(...),
    descripcion: str = Form(...),
    fecha: date = Form(...),
    hora: time = Form(...),
    file: UploadFile = File(None)):

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    if file:
        # Guardar temporalmente el archivo
        file_location = f"static/temp/{file.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Abrir la imagen y comprobar el tamaño
        try:
            with Image.open(file_location) as img:
                if img.size < (200, 200):
                    raise HTTPException(status_code=400, detail="La imagen tiene que ser mayor a 200x200")
                elif img.size > (9000, 9000):
                    raise HTTPException(status_code=400, detail="La imagen tiene que ser menor a 9000x9000")
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid image file")

        # Mover el archivo al directorio final si pasa las validaciones
        final_location = f"static/images/eventos/{file.filename}"
        shutil.move(file_location, final_location)

        # Subir la imagen al servidor FTP con la ruta completa
        ftp_path = "/static/images/eventos"
        with ftp_connect() as ftp:
            create_ftp_directory(ftp, ftp_path)
            with open(final_location, 'rb') as f:
                ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

        # Generar la URL pública del archivo en el servidor FTP
        base_url = "https://test.santiagotulantepec.com"
        imagen_url = f"{base_url}{ftp_path}/{file.filename}"

        # Actualizar los datos en la base de datos
        query = 'UPDATE eventos SET titulo=%s, descripcion=%s, fecha=%s, hora=%s, imagen=%s, ruta=%s WHERE id_evento=%s'
        evento_data = (titulo, descripcion, fecha, hora, file.filename, imagen_url, id_evento)

    else:
        # Actualizar los datos en la base de datos sin cambiar la imagen
        query = 'UPDATE eventos SET titulo=%s, descripcion=%s, fecha=%s, hora=%s WHERE id_evento=%s'
        evento_data = (titulo, descripcion, fecha, hora, id_evento)

    cursor.execute(query, evento_data)
    connection.commit()

    # Convertir la fecha y hora a cadenas ISO 8601
    fecha_iso = fecha.isoformat()
    hora_iso = hora.isoformat()

    return JSONResponse(content={
        "id_evento": id_evento,
        "titulo": titulo,
        "descripcion": descripcion,
        "fecha": fecha_iso,
        "hora": hora_iso,
        "imagen": file.filename if file else "No se cambió la imagen"
    })

# Borrar un event
@app.delete("/evento/borrar/{id_evento}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un evento", tags=['Eventos'])
def borrar_evento(id_evento: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    cursor.execute("SELECT imagen FROM eventos WHERE id_evento=%s", (id_evento,))
    evento = cursor.fetchone()

    if not evento:
        raise HTTPException(status_code=404, detail="Evento no encontrado")

    imagen = evento[0]
    ftp = ftp_connect()
    
    # Construir la ruta completa del archivo en el servidor FTP
    ftp_path = f"/static/images/eventos"
    file_location = f"{ftp_path}/{imagen}"

    # Intentar eliminar el archivo del servidor FTP
    try:
        ftp.delete(file_location)
    except Exception as e:
        print(f"Error al eliminar archivo del servidor FTP: {e}")

    cursor.execute("DELETE FROM eventos WHERE id_evento=%s", (id_evento,))
    connection.commit()

    return JSONResponse(content={"message": "Evento borrado correctamente", "id_evento": id_evento})


@app.get("/bot",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los contactos existentes", tags=['ChatBot'])
def listar_bot():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM bot")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id': row[0],
                    'nombre': row[1],
                    'correo':row[2],
                    'problema':row[3],
                    'area':row[4]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay problemas con el bot en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/bot/{id_bot}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar un asunto con el Bot en la bd", tags=['ChatBot'])
def detalle_bot(id_bot:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM bot WHERE id = %s"
        cursor.execute(query, (id_bot,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id': row[0],
                    'nombre': row[1],
                    'correo':row[2],
                    'problema':row[3],
                    'area':row[4]
                }
                respuesta.append(dato)
            

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe ese problema con el bot en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/bot/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un asunto", tags=['ChatBot'])
def crear_bot(bot: Bot):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar nuevo evento en la base de datos
        query = "INSERT INTO bot (nombre, correo, problema,area) VALUES (%s, %s, %s, %s)"
        evento_data = (bot.nombre, bot.correo, bot.problema, bot.area)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'nombre': bot.nombre,
            'correo': bot.correo,
            'problema': bot.problema,
            'area': bot.area
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar un problema con el bot en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear un problema con el bot")
    finally:
        cursor.close()
        connection.close()

@app.put("/bot/editar/{id_bot}",status_code=status.HTTP_200_OK, summary="Endpoint para editar un asunto con el bot en la base de datos", tags=['ChatBot'])
def editar_bot(bot: Bot, id_bot:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar nuevo usuario en la base de datos
        query = "UPDATE bot SET nombre = %s, correo= %s, problema= %s, area = %s WHERE id = %s"
        evento_data = (bot.nombre,bot.correo,bot.problema,bot.area, id_bot)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'nombre': bot.nombre,
            'correo': bot.correo,
            'problema': bot.problema,
            'area':bot.area
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar problema con el bot en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar problema con el bot")
    finally:
        cursor.close()
        connection.close()

@app.delete("/bot/editar/{id_bot}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un contacto", tags=['ChatBot'])
def borrar_bot(id_bot: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si el aviso existe y obtener la información del archivo
    cursor.execute("SELECT * FROM bot WHERE id=%s", (id_bot,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Ubicacion no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM bot WHERE id =%s", (id_bot,))
    connection.commit()

    return JSONResponse(content={"message": "Aviso borrado correctamente", "aviso_id": id_bot})

@app.get("/encuesta",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las encuestas existentes", tags=['Encuestas'])
def listar_encuestas():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM encuestas")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_encuesta': row[0],
                    'titulo': row[1],
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay encuestas en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/encuesta/{id_encuesta}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una encuesta en la bd", tags=['Encuestas'])
def detalle_encuesta(id_encuesta:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query, (id_encuesta,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_encuesta': row[0],
                    'titulo': row[1],
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe esa encuesta la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/encuesta/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una encuesta", tags=['Encuestas'])
def crear_encuesta(encuestas: Encuestas):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar nueva encuesta en la base de datos
        query = "INSERT INTO encuestas (titulo) VALUES (%s)"
        encuesta_data = (encuestas.titulo,)
        cursor.execute(query, encuesta_data)
        connection.commit()
        
        # Obtener el ID del registro insertado
        encuesta_id = cursor.lastrowid
        
        return {
            'id': encuesta_id,
            'titulo': encuestas.titulo,
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar encuesta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una encuesta")
    finally:
        cursor.close()
        connection.close()

@app.put("/encuesta/editar/{id_encuesta}",status_code=status.HTTP_200_OK, summary="Endpoint para editar una encuesta", tags=['Encuestas'])
def editar_encuesta(encuestas: Encuestas, id_encuesta:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar nuevo usuario en la base de datos
        query = "UPDATE encuestas SET titulo= %s WHERE id_encuesta = %s"
        evento_data = (encuestas.titulo, id_encuesta)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'id_encuesta':id_encuesta,
            'titulo':encuestas.titulo
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar evento en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar evento")
    finally:
        cursor.close()
        connection.close()

@app.delete("/encuesta/borrar/{id_encuesta}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una encuesta", tags=['Encuestas'])
def borrar_encuesta(id_encuesta: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si el aviso existe y obtener la información del archivo
    cursor.execute("SELECT * FROM encuestas WHERE id_encuesta =%s", (id_encuesta,))
    encuesta = cursor.fetchone()
    
    if not encuesta:
        raise HTTPException(status_code=404, detail="Encuesta no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM opcion WHERE id_encuesta =%s", (id_encuesta,))
    cursor.execute("DELETE FROM preguntas WHERE id_encuesta =%s", (id_encuesta,))
    cursor.execute("DELETE FROM encuestas WHERE id_encuesta =%s", (id_encuesta,))
    connection.commit()

    return JSONResponse(content={"message": "Aviso borrado correctamente", "aviso_id": id_encuesta})

@app.get("/buscador_encuesta/{id_encuesta}", status_code=200, summary="Endpoint para buscar una encuesta completa", tags=['Encuestas'])
def obtener_encuesta(id_encuesta: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    try:
        # Obtener título de la encuesta
        query_encuesta = "SELECT id_encuesta, titulo FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query_encuesta, (id_encuesta,))
        encuesta = cursor.fetchone()
        if not encuesta:
            raise HTTPException(status_code=404, detail="Encuesta no encontrada")

        # Obtener preguntas relacionadas a la encuesta
        query_preguntas = "SELECT id_pregunta, pregunta, tipo FROM preguntas WHERE id_encuesta = %s"
        cursor.execute(query_preguntas, (id_encuesta,))
        preguntas = cursor.fetchall()

        for pregunta in preguntas:
            if pregunta['tipo'] in ['radio', 'checkbox']:
                # Obtener opciones para la pregunta
                query_opciones = "SELECT id_opcion, opcion FROM opcion WHERE id_pregunta = %s"
                cursor.execute(query_opciones, (pregunta['id_pregunta'],))
                opciones = cursor.fetchall()
                pregunta['opciones'] = opciones

        encuesta['preguntas'] = preguntas
        return encuesta
    except mysql.connector.Error as err:
        print(f"Error al obtener datos de la encuesta: {err}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
    finally:
        cursor.close()
        connection.close()


@app.get("/pregunta",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las encuestas existentes", tags=['Preguntas'])
def listar_preguntas():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM preguntas")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_pregunta': row[0],
                    'id_encuesta': row[1],
                    'pregunta': row[2],
                    'tipo':row[3]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay preguntas en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/pregunta/{id_encuesta}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una pregunta en la bd", tags=['Preguntas'])
def detalle_pregunta(id_encuesta:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM preguntas WHERE id_encuesta = %s"
        cursor.execute(query, (id_encuesta,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_pregunta': row[0],
                    'id_encuesta': row[1],
                    'pregunta': row[2],
                    'tipo':row[3]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe esa encuesta la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/pregunta/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una pregunta", tags=['Preguntas'])
def crear_pregunta(pregunta: Preguntas):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el id_encuesta existe en la tabla encuestas
        query_check_encuesta = "SELECT id_encuesta FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query_check_encuesta, (pregunta.id_encuesta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La encuesta no existe")
        
        # Validar los valores de pregunta_abierta y pregunta_cerrada_multiple
        if pregunta.tipo not in ['text', 'radio', 'checkbox']:
            raise HTTPException(status_code=400, detail="El valor de 'pregunta_abierta' debe ser text, radio, checkbox")
        
        # Insertar nueva pregunta en la base de datos
        query = "INSERT INTO preguntas (id_encuesta, pregunta, tipo) VALUES (%s,%s,%s)"
        pregunta_data = (pregunta.id_encuesta, pregunta.pregunta, pregunta.tipo)
        cursor.execute(query, pregunta_data)
        connection.commit()
        
        # Obtener el ID del registro insertado
        pregunta_id = cursor.lastrowid

        return {
            'id_pregunta': pregunta_id,
            'id_encuesta': pregunta.id_encuesta,
            'pregunta': pregunta.pregunta,
            'tipo': pregunta.tipo
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar pregunta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una pregunta")
    finally:
        cursor.close()
        connection.close()
        
@app.put("/pregunta/editar/{id_pregunta}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una pregunta", tags=['Preguntas'])
def editar_pregunta(pregunta: Preguntas, id_pregunta: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el id_encuesta existe en la tabla encuestas
        query_check_encuesta = "SELECT id_encuesta FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query_check_encuesta, (pregunta.id_encuesta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La encuesta no existe")
        
        # Actualizar pregunta en la base de datos
        query = "UPDATE preguntas SET pregunta = %s WHERE id_pregunta = %s"
        pregunta_data = (pregunta.pregunta, id_pregunta)
        cursor.execute(query, pregunta_data)
        connection.commit()

        return {
            'detail': 'Pregunta actualizada correctamente',
            'pregunta': pregunta.pregunta
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar la pregunta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar la pregunta")
    finally:
        cursor.close()
        connection.close()


@app.delete("/pregunta/borrar/{id_pregunta}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una encuesta", tags=['Preguntas'])
def borrar_pregunta(id_pregunta: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si el aviso existe y obtener la información del archivo
    cursor.execute("SELECT * FROM preguntas WHERE id_pregunta =%s", (id_pregunta,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Ubicacion no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM opcion WHERE id_encuesta =%s", (id_pregunta,))
    cursor.execute("DELETE FROM preguntas WHERE id_pregunta =%s", (id_pregunta,))
    connection.commit()

    return JSONResponse(content={"message": "Aviso borrado correctamente", "id_pregunta": id_pregunta})

@app.get("/opcion",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las opciones existentes", tags=['Opciones'])
def listar_opciones():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM opcion")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_opcion':row[0],
                    'id_pregunta': row[1],
                    'id_encuesta': row[2],
                    'opcion': row[3]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay opciones en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/opcion/{id_encuesta}/{id_pregunta}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una opcion en la bd", tags=['Opciones'])
def detalle_opcion(id_encuesta:int, id_pregunta:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM opcion WHERE id_encuesta = %s AND id_pregunta = %s"
        cursor.execute(query, (id_encuesta, id_pregunta))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_opcion':row[0],
                    'id_pregunta': row[1],
                    'id_encuesta': row[2],
                    'opcion': row[3]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe esa opcion en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/opcion/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una opcion", tags=['Opciones'])
def crear_opcion(opcion: Opciones):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si la encuesta existe
        query_check_encuesta = "SELECT id_encuesta FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query_check_encuesta, (opcion.id_encuesta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="La encuesta no existe")
        
        # Verificar si la pregunta existe
        query_check_pregunta = "SELECT id_pregunta, tipo FROM preguntas WHERE id_pregunta = %s"
        cursor.execute(query_check_pregunta, (opcion.id_pregunta,))
        pregunta = cursor.fetchone()
        if pregunta is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="La pregunta no existe")

        # Verificar si la pregunta es de tipo 'text'
        if pregunta[1] == 'text':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La pregunta es abierta y no debería tener opciones")

        # Insertar la opción en la base de datos
        query = "INSERT INTO opcion (id_pregunta, id_encuesta, opcion) VALUES (%s, %s, %s)"
        cursor.execute(query, (opcion.id_pregunta, opcion.id_encuesta, opcion.opcion))
        connection.commit()
        return {
            'id_pregunta': opcion.id_pregunta,
            'id_encuesta': opcion.id_encuesta,
            'opcion': opcion.opcion
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar opción en la base de datos: {err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno al crear una opción")
    finally:
        cursor.close()
        connection.close()


@app.put("/opcion/editar/{id_opcion}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una opcion", tags=['Opciones'])
def editar_opcion(opcion: EditarOpcion, id_opcion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Actualizar opción en la base de datos
        query = "UPDATE opcion SET opcion = %s WHERE id_opcion = %s"
        evento_data = (opcion.opcion, id_opcion)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'opcion': opcion.opcion
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar la opcion en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar opcion")
    finally:
        cursor.close()
        connection.close()

@app.delete("/opcion/borrar/{id_opcion}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una opcion", tags=['Opciones'])
def borrar_opcion(id_opcion: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si el aviso existe y obtener la información del archivo
    cursor.execute("SELECT * FROM opcion WHERE id_opcion =%s", (id_opcion,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Ubicacion no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM opcion WHERE id_opcion =%s", (id_opcion,))
    connection.commit()

    return JSONResponse(content={"message": "Aviso borrado correctamente", "id_pregunta": id_opcion})

@app.get("/respuesta_abierta",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las respuestas abiertas dadas existentes", tags=['Respuestas_abiertas'])
def listar_respuestas_abiertas():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM respuesta_abierta")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_respuesta_abierta':row[0],
                    'id_pregunta': row[1],
                    'id_encuesta': row[2],
                    'respuesta': row[3]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay respuestas abiertas en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/respuesta_abierta/{id_encuesta}/{id_pregunta}", status_code=200, summary="Endpoint para obtener respuestas abiertas de una pregunta", tags=['Respuestas_abiertas'])
def obtener_respuestas_abiertas(id_encuesta: int, id_pregunta: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    try:
        query_respuestas_abiertas = "SELECT respuesta FROM respuesta_abierta WHERE id_encuesta = %s AND id_pregunta = %s"
        cursor.execute(query_respuestas_abiertas, (id_encuesta, id_pregunta))
        respuestas_abiertas = cursor.fetchall()
        return respuestas_abiertas
    except mysql.connector.Error as err:
        print(f"Error al obtener respuestas abiertas: {err}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
    finally:
        cursor.close()
        connection.close()

@app.get("/respuesta_abierta/{id_respuesta_abierta}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una respuesta abierta en la bd", tags=['Respuestas_abiertas'])
def detalle_respuesta_abierta(id_respuesta_abierta:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM respuesta_abierta WHERE id_respuesta_abierta = %s"
        cursor.execute(query, (id_respuesta_abierta,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_respuesta_abierta':row[0],
                    'id_pregunta': row[1],
                    'id_encuesta': row[2],
                    'respuesta': row[3]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe una respuesta abierta con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/respuesta_abierta/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una respuesta abierta", tags=['Respuestas_abiertas'])
def crear_respuesta_abierta(respuesta:Respuesta_abierta):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el id_encuesta existe en la tabla encuestas
        query_check_encuesta = "SELECT 1 FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query_check_encuesta, (respuesta.id_encuesta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La encuesta no existe")
        
        # Verificar si el id_pregunta existe en la tabla encuestas
        query_check_pregunta_1 = "SELECT 1 FROM preguntas WHERE id_pregunta = %s"
        cursor.execute(query_check_pregunta_1, (respuesta.id_pregunta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La pregunta no existe")

        # Insertar nuevo evento en la base de datos
        query = "INSERT INTO respuesta_abierta (id_pregunta, id_encuesta, respuesta) VALUES (%s,%s,%s)"
        evento_data = (respuesta.id_pregunta, respuesta.id_encuesta, respuesta.respuesta)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'id_pregunta': respuesta.id_pregunta,
            'id_encuesta': respuesta.id_encuesta,
            'respuesta': respuesta.respuesta
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar pregunta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una opcion")
    finally:
        cursor.close()
        connection.close()

@app.put("/respuesta_abierta/editar/{id_pregunta_abierta}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una respuesta_abierta", tags=['Respuestas_abiertas'])
def editar_respuesta_abierta(respuesta:Editar_respuesta_abierta, id_pregunta_abierta: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Actualizar respuesta abierta en la base de datos
        query = "UPDATE respuesta_abierta SET respuesta = %s WHERE id_respuesta_abierta = %s"
        evento_data = (respuesta.respuesta, id_pregunta_abierta)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'nueva respuesta': respuesta.respuesta
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar la respuesta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar la respuesta")
    finally:
        cursor.close()
        connection.close()

@app.delete("/respuesta_abierta/borrar/{id_respuesta_abierta}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una respuesta abierta", tags=['Respuestas_abiertas'])
def borrar_respuesta_abierta(id_respuesta_abierta: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la repuesta existe
    cursor.execute("SELECT * FROM respuesta_abierta WHERE id_respuesta_abierta =%s", (id_respuesta_abierta,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Respuesta no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM respuesta_abierta WHERE id_respuesta_abierta =%s", (id_respuesta_abierta,))
    connection.commit()

    return JSONResponse(content={"message": "Respuesta borrada correctamente", "id_respuesta_abierta": id_respuesta_abierta})

@app.get("/respuesta_cerrada",status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las respuestas cerradas existentes", tags=['Respuestas_cerradas'])
def listar_respuestas_cerradas():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM respuesta_cerrada")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_respuesta':row[0],
                    'id_opcion':row[1],
                    'id_pregunta': row[2],
                    'id_encuesta': row[3]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay respuestas cerradas en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/respuesta_cerrada/{id_encuesta}/{id_pregunta}/{id_opcion}", status_code=200, summary="Endpoint para obtener respuestas cerradas de una pregunta y opción", tags=['Respuestas_cerradas'])
def obtener_respuestas_cerradas(id_encuesta: int, id_pregunta: int, id_opcion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    try:
        query_respuestas_cerradas = "SELECT COUNT(*) AS total_respuestas FROM respuesta_cerrada WHERE id_encuesta = %s AND id_pregunta = %s AND id_opcion = %s"
        cursor.execute(query_respuestas_cerradas, (id_encuesta, id_pregunta, id_opcion))
        total_respuestas = cursor.fetchone()
        return total_respuestas
    except mysql.connector.Error as err:
        print(f"Error al obtener respuestas cerradas: {err}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
    finally:
        cursor.close()
        connection.close()

@app.get("/respuesta_cerrada/{id_respuesta_cerrada}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar una respuesta cerrada en la bd", tags=['Respuestas_cerradas'])
def detalle_respuesta_cerrada(id_respuesta_cerrada:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM respuesta_cerrada WHERE id_respuesta = %s"
        cursor.execute(query, (id_respuesta_cerrada,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_respuesta':row[0],
                    'id_opcion':row[1],
                    'id_pregunta': row[2],
                    'id_encuesta': row[3]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe una respuesta cerrada con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/respuesta_cerrada/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una respuesta cerrada", tags=['Respuestas_cerradas'])
def crear_respuesta_cerrada(respuesta:Respuesta_cerrada):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el id_encuesta existe en la tabla encuestas
        query_check_encuesta = "SELECT 1 FROM encuestas WHERE id_encuesta = %s"
        cursor.execute(query_check_encuesta, (respuesta.id_encuesta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La encuesta no existe")
        
        # Verificar si el id_pregunta existe en la tabla preguntas
        query_check_pregunta_1 = "SELECT 1 FROM preguntas WHERE id_pregunta = %s"
        cursor.execute(query_check_pregunta_1, (respuesta.id_pregunta,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La pregunta no existe")
        
        # Verificar si el id_opcion existe en la tabla opcion
        query_check_pregunta_1 = "SELECT 1 FROM opcion WHERE id_opcion = %s"
        cursor.execute(query_check_pregunta_1, (respuesta.id_opcion,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="La opcion no existe")

        # Insertar una respesta cerrada en la base de datos
        query = "INSERT INTO respuesta_cerrada (id_opcion, id_pregunta, id_encuesta) VALUES (%s,%s,%s)"
        evento_data = (respuesta.id_opcion, respuesta.id_pregunta, respuesta.id_encuesta)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'id_opcion': respuesta.id_opcion,
            'id_pregunta': respuesta.id_pregunta,
            'id_encuesta': respuesta.id_encuesta
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar pregunta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una opcion")
    finally:
        cursor.close()
        connection.close()

@app.put("/respuesta_cerrada/editar/{id_pregunta_cerrada}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una respuesta cerrada", tags=['Respuestas_cerradas'])
def editar_respuesta_cerrada(respuesta:Editar_respuesta_cerrada, id_pregunta_abierta: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Actualizar respuesta abierta en la base de datos
        query = "UPDATE respuesta_abierta SET respuesta = %s WHERE id_respuesta_abierta = %s"
        evento_data = (respuesta.id_opcion, id_pregunta_abierta)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'nueva opcion seleccionada': respuesta.id_opcion
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar la respuesta en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar la respuesta")
    finally:
        cursor.close()
        connection.close()

@app.delete("/respuesta_cerrada/borrar/{id_respuesta_cerrada}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una respuesta cerrada", tags=['Respuestas_cerradas'])
def borrar_respuesta_cerrada(id_respuesta_cerrada: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la repuesta existe
    cursor.execute("SELECT * FROM respuesta_cerrada WHERE id_respuesta =%s", (id_respuesta_cerrada,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Respuesta no encontrada")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM respuesta_cerrada WHERE id_respuesta =%s", (id_respuesta_cerrada,))
    connection.commit()

    return JSONResponse(content={"message": "Respuesta borrada correctamente", "id_respuesta_cerrada": id_respuesta_cerrada})

@app.get("/articulo",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los articulos existentes", tags=['Articulos'])
def listar_articulos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM articulos")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_articulo':row[0],
                    'num_articulo':row[1]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay articulos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/articulo/{id_articulo}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar articulos en la bd", tags=['Articulos'])
def detalle_articulo(id_articulo:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM articulos WHERE id_articulo = %s"
        cursor.execute(query, (id_articulo,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_articulo':row[0],
                    'num_articulo':row[1]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe un articulo con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/articulo/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un articulo", tags=['Articulos'])
def crear_articulo(articulo:Articulo):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar una respesta cerrada en la base de datos
        query = "INSERT INTO articulos (num_articulo) VALUES (%s)"
        evento_data = (articulo.num_articulo, )
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'num_articulo': articulo.num_articulo
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar articulo en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear un articulo")
    finally:
        cursor.close()
        connection.close()

@app.put("/articulo/editar/{id_articulo}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un articulo", tags=['Articulos'])
def editar_articulo(articulo:Articulo, id_articulo: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Actualizar respuesta abierta en la base de datos
        query = "UPDATE articulos SET num_articulo = %s WHERE id_articulo = %s"
        evento_data = (articulo.num_articulo, id_articulo)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'Nueva articulo editado': articulo.num_articulo
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar el articulo en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar el articulo")
    finally:
        cursor.close()
        connection.close()

@app.delete("/articulo/borrar/{id_articulo}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un articulo", tags=['Articulos'])
def borrar_articulo(id_articulo: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la repuesta existe
    cursor.execute("SELECT * FROM articulos WHERE id_articulo =%s", (id_articulo,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Articulo no encontrado")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM articulos WHERE id_articulo =%s", (id_articulo,))
    connection.commit()

    return JSONResponse(content={"message": "Articulo borrado correctamente", "id_articulo": id_articulo})

# Endpoint para listar todas las fracciones
@app.get("/fraccion", status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las fracciones existentes", tags=['Fracciones'])
def listar_fraccion():
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        cursor.execute("SELECT * FROM fracciones")
        datos = cursor.fetchall()
        
        if datos:
            respuesta = []
            for row in datos:
                # Obtener las áreas de la fracción
                areas = obtener_areas_por_fraccion(cursor, row[0])
                
                dato = {
                    'id_fraccion': row[0],
                    'fraccion': row[1],
                    'descripcion': row[2],
                    'num_articulo': row[3],
                    'areas': areas

                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay fracciones en la Base de datos")
    
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Error al conectar con la base de datos: {str(e)}")
    
    finally:
        cursor.close()
        connection.close()

# Función para obtener las áreas de una fracción específica
def obtener_areas_por_fraccion(cursor, id_fraccion):
    query = """
    SELECT a.id_area, a.nombre_area
    FROM areas a
    JOIN fracciones_areas fa ON a.id_area = fa.id_area
    WHERE fa.id_fraccion = %s
    """
    cursor.execute(query, (id_fraccion,))
    areas = []
    for area in cursor.fetchall():
        area_dict = {
            'id_area': area[0],
            'nombre_area': area[1]
        }
        areas.append(area_dict)
    return areas

@app.get("/fraccion/{id_fraccion}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar fracciones en la bd", tags=['Fracciones'])
def detalle_fraccion(id_fraccion:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM fracciones WHERE id_fraccion = %s"
        cursor.execute(query, (id_fraccion,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                areas = obtener_areas_por_fraccion(cursor, row[0])
                dato = {
                    'id_fraccion':row[0],
                    'fraccion':row[1],
                    'descripcion': row[2],
                    'num_articulo': row[3],
                    'areas': areas
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe una fraccion con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()
# Endpoint para buscar fracciones por área y/o número de artículo
@app.get("/fracciones/busqueda", status_code=status.HTTP_200_OK, summary="Buscar fracciones por área y/o número de artículo", tags=['Fracciones'])
def buscar_fracciones(area: str = Query(None, description="Nombre del área a buscar"), num_articulo: str = Query(None, description="Número del artículo a buscar")):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Construir la consulta SQL dinámicamente según los parámetros proporcionados
    base_query = """
    SELECT f.id_fraccion, f.fraccion, f.descripcion, f.num_articulo
    FROM fracciones f
    LEFT JOIN fracciones_areas fa ON f.id_fraccion = fa.id_fraccion
    LEFT JOIN areas a ON fa.id_area = a.id_area
    """
    conditions = []
    parameters = []

    if area:
        conditions.append("a.nombre_area = %s")
        parameters.append(area)

    if num_articulo:
        conditions.append("f.num_articulo = %s")
        parameters.append(num_articulo)

    # Verifica que al menos un parámetro haya sido proporcionado
    if not conditions:
        raise HTTPException(status_code=400, detail="Debe proporcionar al menos un parámetro de búsqueda")

    query = base_query + " WHERE " + " AND ".join(conditions)
    
    try:
        cursor.execute(query, parameters)
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                # Obtener las áreas de la fracción
                areas = obtener_areas_por_fraccion(cursor, row[0])

                dato = {
                    'id_fraccion': row[0],
                    'fraccion': row[1],
                    'descripcion': row[2],
                    'num_articulo': row[3],
                    'areas': areas
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No se encontraron fracciones con los criterios especificados")
    finally:
        cursor.close()
        connection.close()

# Función para obtener las áreas de una fracción específica
def obtener_areas_por_fraccion(cursor, id_fraccion):
    query = """
    SELECT a.id_area, a.nombre_area
    FROM areas a
    JOIN fracciones_areas fa ON a.id_area = fa.id_area
    WHERE fa.id_fraccion = %s
    """
    cursor.execute(query, (id_fraccion,))
    areas = []
    for area in cursor.fetchall():
        area_dict = {
            'id_area': area[0],
            'nombre_area': area[1]
        }
        areas.append(area_dict)
    return areas

@app.post("/fraccion/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una fracción", tags=['Fracciones'])
def crear_fraccion(fraccion: Fraccion):
    print("Datos recibidos:", fraccion)  # Agrega esta línea para ver los datos recibidos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar fracción en la base de datos
        query = "INSERT INTO fracciones (fraccion, descripcion, num_articulo) VALUES (%s, %s, %s)"
        fraccion_data = (fraccion.fraccion, fraccion.descripcion, fraccion.num_articulo)
        cursor.execute(query, fraccion_data)
        fraccion_id = cursor.lastrowid
        
        # Insertar relaciones en fracciones_areas
        for area_id in fraccion.areas:
            query = "INSERT INTO fracciones_areas (id_fraccion, id_area) VALUES (%s, %s)"
            cursor.execute(query, (fraccion_id, area_id))
        
        connection.commit()
        return {
            'fraccion': fraccion.fraccion,
            'descripcion': fraccion.descripcion,
            'num_articulo': fraccion.num_articulo,
            'areas': fraccion.areas
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar fracción en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una fracción")
    finally:
        cursor.close()
        connection.close()


# Endpoint para editar una fracción
@app.put("/fraccion/editar/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una fracción", tags=['Fracciones'])
def editar_fraccion(fraccion: Fraccion, id_fraccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)  # Asegúrate de usar dictionary=True para obtener resultados como diccionarios
    try:
        # Obtener fracción actual
        cursor.execute("SELECT * FROM fracciones WHERE id_fraccion = %s", (id_fraccion,))
        fraccion_actual = cursor.fetchone()

        if fraccion_actual is None:
            raise HTTPException(status_code=404, detail="Fracción no encontrada")

        # Verificar y actualizar los campos de la fracción
        if fraccion.descripcion != fraccion_actual['descripcion'] or fraccion.num_articulo != fraccion_actual['num_articulo'] or fraccion.fraccion != fraccion_actual['fraccion']:
            query = "UPDATE fracciones SET descripcion = %s, num_articulo = %s, fraccion = %s WHERE id_fraccion = %s"
            cursor.execute(query, (fraccion.descripcion, fraccion.num_articulo, fraccion.fraccion, id_fraccion))

        # Obtener áreas actuales relacionadas con la fracción
        cursor.execute("SELECT id_area FROM fracciones_areas WHERE id_fraccion = %s", (id_fraccion,))
        areas_actuales = [row['id_area'] for row in cursor.fetchall()]

        # Determinar qué áreas agregar o eliminar
        areas_a_agregar = set(fraccion.areas) - set(areas_actuales)
        areas_a_eliminar = set(areas_actuales) - set(fraccion.areas)

        # Agregar nuevas relaciones en fracciones_areas
        for area_id in areas_a_agregar:
            cursor.execute("INSERT INTO fracciones_areas (id_fraccion, id_area) VALUES (%s, %s)", (id_fraccion, area_id))

        # Eliminar relaciones no deseadas en fracciones_areas
        for area_id in areas_a_eliminar:
            cursor.execute("DELETE FROM fracciones_areas WHERE id_fraccion = %s AND id_area = %s", (id_fraccion, area_id))

        connection.commit()
        return {
            'id_fraccion': id_fraccion,
            'descripcion': fraccion.descripcion,
            'num_articulo': fraccion.num_articulo,
            'areas': fraccion.areas
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar la fracción en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar la fracción")
    finally:
        cursor.close()
        connection.close()



@app.delete("/fraccion/borrar/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una fracción", tags=['Fracciones'])
def borrar_fraccion(id_fraccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la fracción existe
    cursor.execute("SELECT * FROM fracciones WHERE id_fraccion = %s", (id_fraccion,))
    fraccion = cursor.fetchone()

    if not fraccion:
        raise HTTPException(status_code=404, detail="Fracción no encontrada")

    # Obtener documentos relacionados a la fracción
    cursor.execute("SELECT id_documento, documento, ruta FROM documentos WHERE id_fraccion = %s", (id_fraccion,))
    documentos = cursor.fetchall()

    try:
        # Conectarse al servidor FTP
        ftp = ftp_connect()
        try:
            for documento in documentos:
                id_documento, documento_nombre, ruta = documento
                try:
                    ftp.delete(ruta)
                except Exception as e:
                    print(f"Error al eliminar archivo del servidor FTP: {e}")

            ftp.quit()
        except Exception as e:
            print(f"Error al conectar con el servidor FTP: {e}")
            ftp.quit()

        # Eliminar documentos relacionados en la base de datos
        cursor.execute("DELETE FROM documentos WHERE id_fraccion = %s", (id_fraccion,))
        
        # Eliminar relaciones en fracciones_areas
        cursor.execute("DELETE FROM fracciones_areas WHERE id_fraccion = %s", (id_fraccion,))

        # Eliminar la fracción de la base de datos
        cursor.execute("DELETE FROM fracciones WHERE id_fraccion = %s", (id_fraccion,))

        connection.commit()
        return JSONResponse(content={"message": "Fracción y documentos relacionados borrados correctamente", "id_fraccion": id_fraccion})

    except mysql.connector.Error as err:
        print(f"Error al borrar la fracción y documentos en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar la fracción y documentos")

    finally:
        cursor.close()
        connection.close()

@app.get("/areas/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Endpoint para obtener áreas de una fracción", tags=['Áreas'])
def get_areas_fraccion(id_fraccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    try:
        query = """
        SELECT a.id_area, a.nombre_area 
        FROM fracciones_areas fa
        JOIN areas a ON fa.id_area = a.id_area
        WHERE fa.id_fraccion = %s
        """
        cursor.execute(query, (id_fraccion,))
        areas = cursor.fetchall()
        return areas
    except mysql.connector.Error as err:
        print(f"Error al obtener las áreas de la fracción: {err}")
        raise HTTPException(status_code=500, detail="Error interno al obtener las áreas de la fracción")
    finally:
        cursor.close()
        connection.close()

@app.get("/areas",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los años existentes", tags=['Años'])
def listar_areas():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM areas")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_area':row[0],
                    'nombre_area':row[1],
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay años en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/year",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los años existentes", tags=['Años'])
def listar_años():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM años")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_año':row[0],
                    'año':row[1],
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay años en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/year/{id_año}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar años en la bd", tags=['Años'])
def detalle_año(id_año:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM años WHERE id_año = %s"
        cursor.execute(query, (id_año,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_año':row[0],
                    'año':row[1],
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe un año con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()


    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Actualizar respuesta abierta en la base de datos
        query = "UPDATE años SET año = %s, id_fraccion = %s WHERE id_año = %s"
        evento_data = (año.año, año.id_fraccion, id_año)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'id_año':id_año,
            'año': año.año,
            'id_fraccion': año.id_fraccion
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar el año en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar el año")
    finally:
        cursor.close()
        connection.close()

@app.delete("/year/borrar/{id_año}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un año", tags=['Años'])
def borrar_año(id_año: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la repuesta existe
    cursor.execute("SELECT * FROM años WHERE id_año =%s", (id_año,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Año no encontrado")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM años WHERE id_año =%s", (id_año,))
    connection.commit()

    return JSONResponse(content={"message": "Año borrado correctamente", "id_año": id_año})

@app.get("/documento",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los documentos existentes", tags=['Documentos'])
def listar_documentos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM documentos")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_documento':row[0],
                    'documento':row[1],
                    'ruta':row[2],
                    'trimestre': row[3],
                    'año':row[4],
                    'id_fraccion':row[5]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay documentos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/documento/{id_documento}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar un documento en la bd", tags=['Documentos'])
def detalle_documento(id_documento:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM documentos WHERE id_documento = %s"
        cursor.execute(query, (id_documento,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_documento':row[0],
                    'documento':row[1],
                    'ruta':row[2],
                    'trimestre': row[3],
                    'año':row[4],
                    'id_fraccion':row[5]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe un documento con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/documento/fraccion/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Buscar documentos por ID de fracción", tags=['Documentos'])
def buscar_documentos_por_fraccion(id_fraccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM documentos WHERE id_fraccion = %s"
        cursor.execute(query, (id_fraccion,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_documento': row[0],
                    'documento': row[1],
                    'ruta': row[2],
                    'trimestre': row[3],
                    'año': row[4],
                    'id_fraccion': row[5]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existen documentos con esa fracción en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/documento/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un documento", tags=['Documentos'])
async def crear_documento(
    id_fraccion: int = Form(...),
    año: str = Form(...),
    trimestre: str = Form(...),
    file: UploadFile = File(...)):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Obtener el fraccion y num_articulo desde la base de datos
        cursor.execute("""
            SELECT f.fraccion, a.num_articulo 
            FROM fracciones f
            JOIN articulos a ON f.num_articulo = a.num_articulo
            WHERE f.id_fraccion = %s
        """, (id_fraccion,))
        fraccion_articulo = cursor.fetchone()
        
        if not fraccion_articulo:
            raise HTTPException(status_code=404, detail="Fracción o artículo no encontrado")
        
        fraccion, articulo = fraccion_articulo

        ftp = ftp_connect()

         # Crear la ruta del archivo en el servidor FTP
        ftp_path = f"/static/documents/transparencia/{str(articulo)}/{fraccion}/{str(año)}"
        create_ftp_directory(ftp, ftp_path)
        file_location = f"{ftp_path}/{file.filename}"

        # Subir el archivo al servidor FTP
        with file.file as f:
            ftp.storbinary(f"STOR {file_location}", f)

        # Generar la URL pública del archivo
        base_url = "https://test.santiagotulantepec.com"
        file_url = f"{base_url}{file_location}"


        # Insertar documento en la base de datos
        query = "INSERT INTO documentos (documento, ruta, trimestre, año, id_fraccion) VALUES (%s, %s ,%s, %s, %s)"
        evento_data = (file.filename, file_url, trimestre, año, id_fraccion)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'id_documento': cursor.lastrowid,
            'documento': file.filename,
            'ruta': file_url,
            'trimestre': trimestre,
            'año': año,
            'id_fraccion': id_fraccion,
            'ruta': file_location
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar documento en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear documento")
    finally:
        cursor.close()
        connection.close()

@app.delete("/documento/borrar/{id_documento}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un documento", tags=['Documentos'])
def borrar_documento(id_documento: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el documento existe y obtener sus detalles
        cursor.execute("SELECT documento, año, id_fraccion FROM documentos WHERE id_documento = %s", (id_documento,))
        documento_data = cursor.fetchone()

        if not documento_data:
            return JSONResponse(content={"message": "Documento no encontrado", "id_documento": id_documento}, status_code=404)
        
        documento, año, id_fraccion = documento_data

        # Obtener fraccion y num_articulo desde la base de datos
        cursor.execute("""
            SELECT f.fraccion, a.num_articulo 
            FROM fracciones f
            JOIN articulos a ON f.num_articulo = a.num_articulo
            WHERE f.id_fraccion = %s
        """, (id_fraccion,))
        fraccion_articulo = cursor.fetchone()

        if not fraccion_articulo:
            raise HTTPException(status_code=404, detail="Fracción o artículo no encontrado")
        
        fraccion, articulo = fraccion_articulo

        # Conectarse al servidor FTP y eliminar el archivo
        ftp = ftp_connect()
        try:
            ftp_path = f"/static/documents/transparencia/{str(articulo)}/{fraccion}/{str(año)}/{documento}"
            ftp.delete(ftp_path)
        except Exception as e:
            print(f"Error al eliminar archivo del servidor FTP: {e}")
        finally:
            ftp.quit()

        # Eliminar el documento de la base de datos
        cursor.execute("DELETE FROM documentos WHERE id_documento = %s", (id_documento,))
        connection.commit()

        return JSONResponse(content={"message": "Documento borrado correctamente", "id_documento": id_documento})

    except mysql.connector.Error as err:
        print(f"Error al borrar el documento en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar documento")
    finally:
        cursor.close()
        connection.close()

@app.get("/color",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los colores existentes", tags=['Colores'])
def listar_colores():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM colores")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_color':row[0],
                    'nombre_color':row[1],
                    'valor_hex': row[2]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay colores en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/color/{id_color}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar colores en la bd", tags=['Colores'])
def detalle_color(id_color:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM colores WHERE id_color = %s"
        cursor.execute(query, (id_color,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_color':row[0],
                    'nombre_color':row[1],
                    'valor_hex': row[2]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe un color con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/color/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un color", tags=['Colores'])
def crear_color(color:Color):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Insertar una respesta cerrada en la base de datos
        query = "INSERT INTO colores (nombre_color, valor_hex) VALUES (%s, %s)"
        evento_data = (color.nombre_color, color.valor_hex)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'nombre_color': color.nombre_color,
            'valor_hex': color.valor_hex
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar color en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear un color")
    finally:
        cursor.close()
        connection.close()

@app.put("/color/editar/{id_color}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un color", tags=['Colores'])
def editar_color(color:Color, id_color:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Actualizar respuesta abierta en la base de datos
        query = "UPDATE colores SET nombre_color = %s, valor_hex = %s WHERE id_color = %s"
        evento_data = (color.nombre_color, color.valor_hex, id_color)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'id_color': id_color,
            'nombre_color': color.nombre_color,
            'valor_hex': color.valor_hex
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al actualizar el color en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar el color")
    finally:
        cursor.close()
        connection.close()

@app.delete("/color/borrar/{id_color}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un color", tags=['Colores'])
def borrar_color(id_color: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la repuesta existe
    cursor.execute("SELECT * FROM colores WHERE id_color =%s", (id_color,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Color no encontrado")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM colores WHERE id_color =%s", (id_color,))
    connection.commit()

    return JSONResponse(content={"message": "Color borrado correctamente", "id_color": id_color})

@app.get("/funcionario", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los funcionarios existentes", tags=['Funcionarios'])
def listar_funcionarios():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM funcionarios")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_funcionario': row[0],
                    'nombre_funcionario': row[1],
                    'puesto': row[2],
                    'institucion': row[3],
                    'telefono': row[4],
                    'correo': row[5],
                    'imagen': row[6],
                    'ruta': row[7]
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay funcionarios en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/funcionario/{id_funcionario}", status_code=status.HTTP_200_OK, summary="Endpoint para obtener un funcionario por su ID", tags=['Funcionarios'])
def detalle_funcionario(id_funcionario: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM funcionarios WHERE id_funcionario = %s"
        cursor.execute(query, (id_funcionario,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_funcionario': row[0],
                    'nombre_funcionario': row[1],
                    'puesto': row[2],
                    'institucion': row[3],
                    'telefono': row[4],
                    'correo': row[5],
                    'imagen': row[6],
                    'ruta': row[7]
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay funcionario con ese ID en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/funcionario/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un nuevo funcionario", tags=['Funcionarios'])
async def crear_funcionario(
    nombre_funcionario: str = Form(...),
    puesto: str = Form(...),
    institucion: str = Form(...),
    telefono: str = Form(...),
    correo: str = Form(...),
    file: UploadFile = File(...)
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Guardar temporalmente el archivo
    file_location = f"static/temp/{file.filename}"
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Validar el tamaño de la imagen
    try:
        with Image.open(file_location) as img:
            if img.size < (200, 200):
                raise HTTPException(status_code=400, detail="La imagen debe tener al menos 200x200 píxeles")
            elif img.size > (9000, 9000):
                raise HTTPException(status_code=400, detail="La imagen debe tener como máximo 9000x9000 píxeles")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Archivo de imagen inválido")

    # Mover el archivo al directorio final
    final_location = f"static/images/funcionarios/{file.filename}"
    shutil.move(file_location, final_location)

     # Subir la imagen al servidor FTP con la ruta completa
    ftp_path = "/static/images/funcionarios"
    with ftp_connect() as ftp:
        create_ftp_directory(ftp, ftp_path)
        with open(final_location, 'rb') as f:
            ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
    base_url = "https://test.santiagotulantepec.com"
    imagen_url = f"{base_url}{ftp_path}/{file.filename}"

    # Insertar datos en la base de datos
    query = 'INSERT INTO funcionarios (nombre_funcionario, puesto, institucion, telefono, correo, imagen, ruta) VALUES (%s,%s,%s,%s,%s,%s,%s)'
    data = (nombre_funcionario, puesto, institucion, telefono, correo, file.filename, imagen_url)
    cursor.execute(query, data)
    connection.commit()

    return JSONResponse(content={
        'nombre_funcionario': nombre_funcionario,
        'puesto': puesto,
        'institucion': institucion,
        'telefono': telefono,
        'correo': correo,
        'imagen': file.filename,
        'ruta': imagen_url
    })

@app.put("/funcionario/editar/{id_funcionario}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un funcionario existente", tags=['Funcionarios'])
async def editar_funcionario(
    id_funcionario: int,
    nombre_funcionario: str = Form(...),
    puesto: str = Form(...),
    institucion: str = Form(...),
    telefono: str = Form(...),  # Cambiado a int si el teléfono es numérico en la base de datos
    correo: str = Form(...),
    file: UploadFile = File(None)
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Verificar si el funcionario existe
        cursor.execute("SELECT imagen FROM funcionarios WHERE id_funcionario = %s", (id_funcionario,))
        funcionario = cursor.fetchone()

        if not funcionario:
            raise HTTPException(status_code=404, detail="Funcionario no encontrado")

        # Procesar el archivo de imagen si se proporciona
        if file:
            file_location = f"static/temp/{file.filename}"
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            try:
                with Image.open(file_location) as img:
                    if img.size < (200, 200):
                        raise HTTPException(status_code=400, detail="La imagen debe ser mayor a 200x200")
                    elif img.size > (9000, 9000):
                        raise HTTPException(status_code=400, detail="La imagen debe ser menor a 9000x9000")
            except Exception as e:
                raise HTTPException(status_code=400, detail="Archivo de imagen inválido")

            final_location = f"static/images/funcionarios/{file.filename}"
            shutil.move(file_location, final_location)

            # Subir la imagen al servidor FTP con la ruta completa
            ftp_path = "/static/images/funcionarios"
            with ftp_connect() as ftp:
                create_ftp_directory(ftp, ftp_path)
                with open(final_location, 'rb') as f:
                    ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
            base_url = "https://test.santiagotulantepec.com"
            imagen_url = f"{base_url}{ftp_path}/{file.filename}"

            # Actualizar la base de datos con la nueva información incluyendo la imagen
            query = 'UPDATE funcionarios SET nombre_funcionario=%s, puesto=%s, institucion=%s, telefono=%s, correo=%s, imagen=%s, ruta=%s WHERE id_funcionario=%s'
            data = (nombre_funcionario, puesto, institucion, telefono, correo, file.filename, imagen_url, id_funcionario)
        else:
            # Actualizar la base de datos sin cambiar la imagen
            query = 'UPDATE funcionarios SET nombre_funcionario=%s, puesto=%s, institucion=%s, telefono=%s, correo=%s WHERE id_funcionario=%s'
            data = (nombre_funcionario, puesto, institucion, telefono, correo, id_funcionario)

        cursor.execute(query, data)
        connection.commit()

        return JSONResponse(content={
            "id_funcionario": id_funcionario,
            "nombre_funcionario": nombre_funcionario,
            "imagen": file.filename if file else "No se cambió la imagen"
        })

    except mysql.connector.Error as err:
        print(f"Error al editar funcionario en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al editar funcionario")

    finally:
        cursor.close()
        connection.close()


@app.delete("/funcionario/borrar/{id_funcionario}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un funcionario existente", tags=['Funcionarios'])
async def borrar_funcionario(id_funcionario: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM funcionarios WHERE id_funcionario=%s", (id_funcionario,))
    funcionario = cursor.fetchone()

    if not funcionario:
        raise HTTPException(status_code=404, detail="Funcionario no encontrado")

    cursor.execute("SELECT imagen FROM funcionarios WHERE id_funcionario=%s", (id_funcionario,))
    funcionario = cursor.fetchone()

    imagen = funcionario[0]
    ftp = ftp_connect()
    
    # Construir la ruta completa del archivo en el servidor FTP
    ftp_path = f"/static/images/funcionarios"
    file_location = f"{ftp_path}/{imagen}"

    # Intentar eliminar el archivo del servidor FTP
    try:
        ftp.delete(file_location)
    except Exception as e:
        print(f"Error al eliminar archivo del servidor FTP: {e}")

    cursor.execute("DELETE FROM funcionarios WHERE id_funcionario=%s", (id_funcionario,))
    connection.commit()

    return JSONResponse(content={"message": "Funcionario borrado correctamente", "id_funcionario": id_funcionario})


# Listar todos los expresidentes
@app.get("/expresidente", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los expresidentes existentes", tags=['Expresidentes'])
def listar_exPresidentes():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM expresidentes")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_expresidente': row[0],
                    'nombre_expresidente': row[1],
                    'periodo': row[2],
                    'imagen': row[3],
                    'ruta': row[4]
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay expresidentes en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Obtener un expresidente por su ID
@app.get("/expresidente/{id_expresidente}", status_code=status.HTTP_200_OK, summary="Endpoint para obtener un expresidente por su ID", tags=['Expresidentes'])
def detalle_exPresidente(id_expresidente: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM expresidentes WHERE id_expresidente = %s"
        cursor.execute(query, (id_expresidente,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_expresidente': row[0],
                    'nombre_expresidente': row[1],
                    'periodo': row[2],
                    'imagen': row[3],
                    'ruta': row[4]
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay expresidente con ese ID en la Base de datos")
    finally:
        cursor.close()
        connection.close()
# Crear un nuevo expresidente
@app.post("/expresidente/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un nuevo expresidente", tags=['Expresidentes'])
async def crear_exPresidente(
    nombre_expresidente: str = Form(...),
    periodo: str = Form(...),
    file: UploadFile = File(...)
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Crear carpeta temp si no existe
    temp_dir = "static/temp"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir, exist_ok=True)

    # Guardar temporalmente el archivo
    file_location = f"{temp_dir}/{file.filename}"
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Validar el tamaño de la imagen
    try:
        with Image.open(file_location) as img:
            if img.size < (200, 200):
                raise HTTPException(status_code=400, detail="La imagen debe tener al menos 200x200 píxeles")
            elif img.size > (9000, 9000):
                raise HTTPException(status_code=400, detail="La imagen debe tener como máximo 9000x9000 píxeles")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Archivo de imagen inválido")

    # Mover el archivo al directorio final
    final_location = f"static/images/expresidentes/{file.filename}"
    shutil.move(file_location, final_location)

     # Subir la imagen al servidor FTP con la ruta completa
    ftp_path = "/static/images/expresidentes"
    with ftp_connect() as ftp:
        create_ftp_directory(ftp, ftp_path)
        with open(final_location, 'rb') as f:
            ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
    base_url = "https://test.santiagotulantepec.com"
    imagen_url = f"{base_url}{ftp_path}/{file.filename}"
    # Insertar datos en la base de datos
    query = 'INSERT INTO expresidentes (nombre_expresidente, periodo, imagen, ruta) VALUES (%s,%s,%s,%s)'
    data = (nombre_expresidente, periodo, file.filename, imagen_url)
    cursor.execute(query, data)
    connection.commit()

    return JSONResponse(content={
        'nombre_expresidente': nombre_expresidente,
        'periodo': periodo,
        'imagen': file.filename,
        'ruta': imagen_url
    })

@app.put("/expresidente/editar/{id_expresidente}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un expresidente existente", tags=['Expresidentes'])
async def editar_exPresidente(
    id_expresidente: int,
    nombre_expresidente: str = Form(...),
    periodo: str = Form(...),
    imagen: UploadFile = File(None)
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    if imagen:
        file_location = f"static/temp/{imagen.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(imagen.file, buffer)

        try:
            with Image.open(file_location) as img:
                if img.size < (200, 200):
                    raise HTTPException(status_code=400, detail="La imagen tiene que ser mayor a 200x200")
                elif img.size > (9000, 9000):
                    raise HTTPException(status_code=400, detail="La imagen tiene que ser menor a 9000x9000")
        except Exception as e:
            raise HTTPException(status_code=400, detail="Archivo de imagen inválido")

        final_location = f"static/images/expresidentes/{imagen.filename}"
        shutil.move(file_location, final_location)

         # Subir la imagen al servidor FTP con la ruta completa
        ftp_path = "/static/images/expresidentes"
        with ftp_connect() as ftp:
            create_ftp_directory(ftp, ftp_path)
            with open(final_location, 'rb') as f:
                ftp.storbinary(f"STOR {ftp_path}/{imagen.filename}", f)

                # Generar la URL pública del archivo en el servidor FTP
        base_url = "https://test.santiagotulantepec.com"
        imagen_url = f"{base_url}{ftp_path}/{imagen.filename}"

        query = 'UPDATE expresidentes SET nombre_expresidente=%s, periodo=%s, imagen=%s, ruta=%s WHERE id_expresidente=%s'
        data = (nombre_expresidente, periodo, imagen.filename, imagen_url, id_expresidente)
    else:
        query = 'UPDATE expresidentes SET nombre_expresidente=%s, periodo=%s WHERE id_expresidente=%s'
        data = (nombre_expresidente, periodo, id_expresidente)

    cursor.execute(query, data)
    connection.commit()

    return JSONResponse(content={
        "id_expresidente": id_expresidente,
        "nombre_expresidente": nombre_expresidente,
        "imagen": imagen.filename if imagen else "No se cambió la imagen"
    })
# Borrar un expresidente existente
@app.delete("/expresidente/borrar/{id_expresidente}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un expresidente existente", tags=['Expresidentes'])
async def borrar_exPresidente(id_expresidente: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM expresidentes WHERE id_expresidente=%s", (id_expresidente,))
    exPresidente = cursor.fetchone()

    if not exPresidente:
        raise HTTPException(status_code=404, detail="Expresidente no encontrado")

    cursor.execute("SELECT imagen FROM expresidentes WHERE id_expresidente=%s", (id_expresidente,))
    exPresidente = cursor.fetchone()

    file_name = exPresidente[0]
    ftp = ftp_connect()
    
    # Construir la ruta completa del archivo en el servidor FTP
    ftp_path = f"/static/images/funcionarios"
    file_location = f"{ftp_path}/{file_name}"

    # Intentar eliminar el archivo del servidor FTP
    try:
        ftp.delete(file_location)
    except Exception as e:
        print(f"Error al eliminar archivo del servidor FTP: {e}")

    cursor.execute("DELETE FROM expresidentes WHERE id_expresidente=%s", (id_expresidente,))
    connection.commit()

    return JSONResponse(content={"message": "Expresidente borrado correctamente", "id_expresidente": id_expresidente})

@app.get("/buzon",status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los colores existentes", tags=['Buzon'])
def listar_buzon():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM buzon_ciudadano")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_buzon':row[0],
                    'nombre':row[1],
                    'telefono': row[2],
                    'correo': row[3],
                    'comentarios':row[4],
                    'dia': row[5]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay quejas ni sugerencias en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/buzon/ordenado", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los colores existentes", tags=['Buzon'])
def listar_buzon_ordenado():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM buzon_ciudadano ORDER BY dia DESC")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_buzon': row[0],
                    'nombre': row[1],
                    'telefono': row[2],
                    'correo': row[3],
                    'comentarios': row[4],
                    'dia': row[5]
                }
                respuesta.append(dato)
            
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay quejas ni sugerencias en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/buzon/{id_buzon}",status_code=status.HTTP_200_OK, summary="Endpoint para buscar quejas en la bd", tags=['Buzon'])
def detalle_buzon(id_buzon:int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM buzon_ciudadano WHERE id_buzon = %s"
        cursor.execute(query, (id_buzon,))
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_buzon':row[0],
                    'nombre':row[1],
                    'telefono': row[2],
                    'correo': row[3],
                    'comentarios':row[4],
                    'dia': row[5]
                }
                respuesta.append(dato)

            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No existe un color con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/buzon/crear", status_code=status.HTTP_200_OK, summary="Endpoint para poner una queja o sugerencia", tags=['Buzon'])
def crear_buzon(buzon: Buzon):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Obtener la fecha de hoy
        fecha_hoy = datetime.datetime.today()

        # Formatear la fecha en el formato YYYY-MM-DD
        fecha_hoy_str = fecha_hoy.strftime('%Y-%m-%d')

        # Insertar una respuesta cerrada en la base de datos
        query = "INSERT INTO buzon_ciudadano (nombre, telefono, correo, comentarios, dia) VALUES (%s, %s, %s, %s, %s)"
        evento_data = (buzon.nombre, buzon.telefono, buzon.correo, buzon.comentarios, fecha_hoy_str)
        cursor.execute(query, evento_data)
        connection.commit()
        return {
            'nombre': buzon.nombre,
            'telefono': buzon.telefono,
            'correo': buzon.correo,
            'comentarios': buzon.comentarios,
            'dia': fecha_hoy_str
        }
    except mysql.connector.Error as err:
        # Manejar errores de la base de datos
        print(f"Error al insertar la sugerencia/queja en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear sugerencia/queja")
    finally:
        cursor.close()
        connection.close()


@app.delete("/buzon/borrar/{id_buzon}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una queja/sugerencia", tags=['Buzon'])
def borrar_buzon(id_buzon: int):
    # Conectar a la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Verificar si la repuesta existe
    cursor.execute("SELECT * FROM buzon_ciudadano WHERE id_buzon =%s", (id_buzon,))
    aviso = cursor.fetchone()
    
    if not aviso:
        raise HTTPException(status_code=404, detail="Color no encontrado")

    # Eliminar el aviso de la base de datos
    cursor.execute("DELETE FROM buzon_ciudadano WHERE id_buzon =%s", (id_buzon,))
    connection.commit()

    return JSONResponse(content={"message": "Queja/Sugerencia borrada correctamente", "id_buzon": id_buzon})


# Endpoint para listar todos los tomos
@app.get("/tomo", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los tomos", tags=['Tomos'])
def listar_tomos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM tomos")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                tomo = {
                    'id_tomo': row[0],
                    'nombre_tomo': row[1],
                    'descripcion': row[2]
                }
                respuesta.append(tomo)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay tomos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Endpoint para buscar un tomo por id
@app.get("/tomo/{id_tomo}", status_code=status.HTTP_200_OK, summary="Endpoint para buscar un tomo por id", tags=['Tomos'])
def detalle_tomo(id_tomo: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM tomos WHERE id_tomo = %s"
        cursor.execute(query, (id_tomo,))
        datos = cursor.fetchall()
        if datos:
            tomo = {
                'id_tomo': datos[0][0],
                'nombre_tomo': datos[0][1],
                'descripcion': datos[0][2]
            }
            return tomo
        else:
            raise HTTPException(status_code=404, detail="No existe un tomo con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Endpoint para crear un tomo
@app.post("/tomo/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un tomo", tags=['Tomos'])
def crear_tomo(tomo: Tomo):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "INSERT INTO tomos (nombre_tomo, descripcion) VALUES (%s, %s)"
        tomo_data = (tomo.nombre_tomo, tomo.descripcion)
        cursor.execute(query, tomo_data)
        connection.commit()
        return {
            'nombre_tomo': tomo.nombre_tomo,
            'descripcion': tomo.descripcion
        }
    except mysql.connector.Error as err:
        print(f"Error al insertar tomo en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear un tomo")
    finally:
        cursor.close()
        connection.close()

# Endpoint para editar un tomo por id
@app.put("/tomo/editar/{id_tomo}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un tomo por id", tags=['Tomos'])
def editar_tomo(id_tomo: int, tomo: Tomo):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "UPDATE tomos SET nombre_tomo = %s, descripcion = %s WHERE id_tomo = %s"
        tomo_data = (tomo.nombre_tomo, tomo.descripcion, id_tomo)
        cursor.execute(query, tomo_data)
        connection.commit()
        return {
            'id_tomo': id_tomo,
            'nombre_tomo': tomo.nombre_tomo,
            'descripcion': tomo.descripcion
        }
    except mysql.connector.Error as err:
        print(f"Error al actualizar el tomo en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar el tomo")
    finally:
        cursor.close()
        connection.close()

# Endpoint para borrar un tomo por id
@app.delete("/tomo/borrar/{id_tomo}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un tomo por id", tags=['Tomos'])
def borrar_tomo(id_tomo: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el tomo existe
        cursor.execute("SELECT * FROM tomos WHERE id_tomo = %s", (id_tomo,))
        tomo = cursor.fetchone()
        if not tomo:
            raise HTTPException(status_code=404, detail="Tomo no encontrado")
        
        # Eliminar el tomo de la base de datos
        cursor.execute("DELETE FROM tomos WHERE id_tomo = %s", (id_tomo,))
        connection.commit()

        return JSONResponse(content={"message": "Tomo borrado correctamente", "id_tomo": id_tomo})
    except mysql.connector.Error as err:
        print(f"Error al borrar el tomo en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar el tomo")
    finally:
        cursor.close()
        connection.close()

# Endpoint para listar todas las secciones
@app.get("/seccion", status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las secciones", tags=['Secciones'])
def listar_secciones():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM seccion")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                seccion = {
                    'id_seccion': row[0],
                    'nombre_seccion': row[1]
                }
                respuesta.append(seccion)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay secciones en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Endpoint para buscar una seccion por id
@app.get("/seccion/{id_seccion}", status_code=status.HTTP_200_OK, summary="Endpoint para buscar una seccion por id", tags=['Secciones'])
def detalle_seccion(id_seccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM seccion WHERE id_seccion = %s"
        cursor.execute(query, (id_seccion,))
        datos = cursor.fetchall()
        if datos:
            seccion = {
                'id_seccion': datos[0][0],
                'nombre_seccion': datos[0][1]
            }
            return seccion
        else:
            raise HTTPException(status_code=404, detail="No existe una seccion con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Endpoint para crear una seccion
@app.post("/seccion/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una seccion", tags=['Secciones'])
def crear_seccion(seccion: Seccion):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "INSERT INTO seccion (nombre_seccion) VALUES (%s)"
        seccion_data = (seccion.nombre_seccion,)
        cursor.execute(query, seccion_data)
        connection.commit()
        return {
            'nombre_seccion': seccion.nombre_seccion
        }
    except mysql.connector.Error as err:
        print(f"Error al insertar seccion en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una seccion")
    finally:
        cursor.close()
        connection.close()

# Endpoint para editar una seccion por id
@app.put("/seccion/editar/{id_seccion}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una seccion por id", tags=['Secciones'])
def editar_seccion(id_seccion: int, seccion: Seccion):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "UPDATE seccion SET nombre_seccion = %s WHERE id_seccion = %s"
        seccion_data = (seccion.nombre_seccion, id_seccion)
        cursor.execute(query, seccion_data)
        connection.commit()
        return {
            'id_seccion': id_seccion,
            'nombre_seccion': seccion.nombre_seccion
        }
    except mysql.connector.Error as err:
        print(f"Error al actualizar la seccion en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar la seccion")
    finally:
        cursor.close()
        connection.close()

# Endpoint para borrar una seccion por id
@app.delete("/seccion/borrar/{id_seccion}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una seccion por id", tags=['Secciones'])
def borrar_seccion(id_seccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si la seccion existe
        cursor.execute("SELECT * FROM seccion WHERE id_seccion = %s", (id_seccion,))
        seccion = cursor.fetchone()
        if not seccion:
            raise HTTPException(status_code=404, detail="Seccion no encontrada")
        
        # Eliminar la seccion de la base de datos
        cursor.execute("DELETE FROM seccion WHERE id_seccion = %s", (id_seccion,))
        connection.commit()

        return JSONResponse(content={"message": "Seccion borrada correctamente", "id_seccion": id_seccion})
    except mysql.connector.Error as err:
        print(f"Error al borrar la seccion en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar la seccion")
    finally:
        cursor.close()
        connection.close()

# Endpoint para listar todas las fracciones CONAC
@app.get("/fraccion-conac", status_code=status.HTTP_200_OK, summary="Endpoint para listar todas las fracciones CONAC", tags=['Fracciones CONAC'])
def listar_fracciones_conac():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM fraccion_conac")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                fraccion = {
                    'id_fraccion': row[0],
                    'nombre_fraccion': row[1]
                }
                respuesta.append(fraccion)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay fracciones CONAC en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Endpoint para buscar una fraccion CONAC por id
@app.get("/fraccion-conac/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Endpoint para buscar una fraccion CONAC por id", tags=['Fracciones CONAC'])
def detalle_fraccion_conac(id_fraccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM fraccion_conac WHERE id_fraccion = %s"
        cursor.execute(query, (id_fraccion,))
        datos = cursor.fetchall()
        if datos:
            fraccion = {
                'id_fraccion': datos[0][0],
                'nombre_fraccion': datos[0][1]
            }
            return fraccion
        else:
            raise HTTPException(status_code=404, detail="No existe una fraccion CONAC con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

# Endpoint para crear una fraccion CONAC
@app.post("/fraccion-conac/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear una fraccion CONAC", tags=['Fracciones CONAC'])
def crear_fraccion_conac(fraccion: FraccionConac):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "INSERT INTO fraccion_conac (nombre_fraccion) VALUES (%s)"
        fraccion_data = (fraccion.nombre_fraccion,)
        cursor.execute(query, fraccion_data)
        connection.commit()
        return {
            'nombre_fraccion': fraccion.nombre_fraccion
        }
    except mysql.connector.Error as err:
        print(f"Error al insertar fraccion CONAC en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear una fraccion CONAC")
    finally:
        cursor.close()
        connection.close()

# Endpoint para editar una fraccion CONAC por id
@app.put("/fraccion-conac/editar/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Endpoint para editar una fraccion CONAC por id", tags=['Fracciones CONAC'])
def editar_fraccion_conac(id_fraccion: int, fraccion: FraccionConac):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "UPDATE fraccion_conac SET nombre_fraccion = %s WHERE id_fraccion = %s"
        fraccion_data = (fraccion.nombre_fraccion, id_fraccion)
        cursor.execute(query, fraccion_data)
        connection.commit()
        return {
            'id_fraccion': id_fraccion,
            'nombre_fraccion': fraccion.nombre_fraccion
        }
    except mysql.connector.Error as err:
        print(f"Error al actualizar la fraccion CONAC en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar la fraccion CONAC")
    finally:
        cursor.close()
        connection.close()

# Endpoint para borrar una fraccion CONAC por id
@app.delete("/fraccion-conac/borrar/{id_fraccion}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar una fraccion CONAC por id", tags=['Fracciones CONAC'])
def borrar_fraccion_conac(id_fraccion: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si la fraccion CONAC existe
        cursor.execute("SELECT * FROM fraccion_conac WHERE id_fraccion = %s", (id_fraccion,))
        fraccion = cursor.fetchone()
        if not fraccion:
            raise HTTPException(status_code=404, detail="Fraccion CONAC no encontrada")
        
        # Eliminar la fraccion CONAC de la base de datos
        cursor.execute("DELETE FROM fraccion_conac WHERE id_fraccion = %s", (id_fraccion,))
        connection.commit()

        return JSONResponse(content={"message": "Fraccion CONAC borrada correctamente", "id_fraccion": id_fraccion})
    except mysql.connector.Error as err:
        print(f"Error al borrar la fraccion CONAC en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar la fraccion CONAC")
    finally:
        cursor.close()
        connection.close()

@app.get("/documento-conac", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los documentos existentes", tags=['Documentos-Conac'])
def listar_documentos():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM documento_conac")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                documento = {
                    'id_documento': row[0],
                    'archivo': row[1],
                    'año': row[2],
                    'trimestre_categoria': row[3],
                    'ruta': row[4],
                    'nombre_tomo': row[5],
                    'nombre_seccion': row[6],
                    'nombre_fraccion': row[7]
                }
                respuesta.append(documento)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay documentos en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/documento-conac/{id_documento}", status_code=status.HTTP_200_OK, summary="Endpoint para buscar un documento en la bd", tags=['Documentos-Conac'])
def detalle_documento(id_documento: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        query = "SELECT * FROM documento_conac WHERE id_documento = %s"
        cursor.execute(query, (id_documento,))
        datos = cursor.fetchone()
        if datos:
            documento = {
                'id_documento': datos[0],
                'archivo': datos[1],
                'año': datos[2],
                'trimestre_categoria': datos[3],
                'ruta': datos[4],
                'nombre_tomo': datos[5],
                'nombre_seccion': datos[6],
                'nombre_fraccion': datos[7]
            }
            return documento
        else:
            raise HTTPException(status_code=404, detail="No existe un documento con ese id en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/documento-conac/crear", status_code=status.HTTP_200_OK, summary="Endpoint para crear un documento", tags=['Documentos-Conac'])
async def crear_documento(
    nombre_tomo: str = Form(...),
    nombre_seccion: str = Form(...),
    trimestre_categoria: str = Form(...),
    nombre_fraccion: str = Form(...),
    año: str = Form(...),
    file: UploadFile = File(...)):

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Validar el nombre del tomo
        cursor.execute("SELECT COUNT(*) FROM tomos WHERE nombre_tomo = %s", (nombre_tomo,))
        if cursor.fetchone()[0] == 0:
            raise HTTPException(status_code=400, detail="El nombre del tomo no es válido")

        # Validar el nombre de la sección
        cursor.execute("SELECT COUNT(*) FROM seccion WHERE nombre_seccion = %s", (nombre_seccion,))
        if cursor.fetchone()[0] == 0:
            raise HTTPException(status_code=400, detail="El nombre de la sección no es válido")

        # Validar el nombre de la fracción
        cursor.execute("SELECT COUNT(*) FROM fraccion_conac WHERE nombre_fraccion = %s", (nombre_fraccion,))
        if cursor.fetchone()[0] == 0:
            raise HTTPException(status_code=400, detail="El nombre de la fracción no es válido")

        ftp = ftp_connect()
        
        try:
            # Crear la ruta del archivo en el servidor FTP
            ftp_path = f"/static/conac/{nombre_tomo}/{nombre_seccion}/{nombre_fraccion}/{año}"
            create_ftp_directory(ftp, ftp_path)
            file_location = f"{ftp_path}/{file.filename}"

            # Subir el archivo al servidor FTP
            with file.file as f:
                ftp.storbinary(f"STOR {file_location}", f)
        
        except Exception as e:
            print(f"Error al subir archivo al servidor FTP: {e}")
            raise HTTPException(status_code=500, detail=f"Error al subir archivo al servidor FTP: {e}")
        
        finally:
            ftp.quit()

        # Generar la URL pública del archivo
        base_url = "https://test.santiagotulantepec.com"
        file_url = f"{base_url}{file_location}"

        # Insertar documento en la base de datos
        query = """
        INSERT INTO documento_conac (archivo, año, trimestre_categoria, ruta, nombre_tomo, nombre_seccion, nombre_fraccion)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        documento_data = (file.filename, año, trimestre_categoria, file_url, nombre_tomo, nombre_seccion, nombre_fraccion)
        cursor.execute(query, documento_data)
        connection.commit()

        return JSONResponse(content={
            'id_documento': cursor.lastrowid,
            'archivo': file.filename,
            'ruta': file_url,
            'trimestre_categoria': trimestre_categoria,
            'año': año,
            'nombre_tomo': nombre_tomo,
            'nombre_seccion': nombre_seccion,
            'nombre_fraccion': nombre_fraccion
        })
    
    except mysql.connector.Error as err:
        print(f"Error al insertar documento en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear documento")
    
    finally:
        cursor.close()
        connection.close()


@app.delete("/documento-conac/borrar/{id_documento}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un documento", tags=['Documentos-Conac'])
def borrar_documento(id_documento: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Verificar si el documento existe y obtener su ruta
        cursor.execute("SELECT archivo, año, nombre_tomo, nombre_seccion, nombre_fraccion FROM documento_conac WHERE id_documento = %s", (id_documento,))
        documento_data = cursor.fetchone()
        
        if documento_data:
            archivo, año, nombre_tomo, nombre_seccion, nombre_fraccion = documento_data

            # Construir la ruta completa del archivo en el FTP
            file_location = f"/static/conac/{nombre_tomo}/{nombre_seccion}/{nombre_fraccion}/{año}/{archivo}"

            # Conectar al servidor FTP y eliminar el archivo
            ftp = ftp_connect()
            try:
                ftp.delete(file_location)
            except Exception as e:
                print(f"Error al eliminar archivo en el servidor FTP: {e}")
                raise HTTPException(status_code=500, detail=f"Error al eliminar archivo en el servidor FTP: {e}")
            
            # Aunque no se encontró el documento, se intenta borrar el registro de la base de datos
            cursor.execute("DELETE FROM documento_conac WHERE id_documento = %s", (id_documento,))
            connection.commit()

            return JSONResponse(content={"message": "Documento no encontrado, pero se eliminó el registro de la base de datos", "id_documento": id_documento})
        
    except mysql.connector.Error as err:
        print(f"Error al borrar documento en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar documento")
    finally:
        cursor.close()
        connection.close()

@app.get("/explora", status_code=status.HTTP_200_OK, summary="Endpoint para listar todos los sitios existentes", tags=['Explora'])
def listar_sitios():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM explora")
        datos = cursor.fetchall()
        if datos:
            respuesta = []
            for row in datos:
                dato = {
                    'id_explora': row[0],
                    'nombre_sitio': row[1],
                    'direccion': row[2],
                    'descripcion': row[3],
                    'imagen': row[4],
                    'ruta': row[5],
                    'categoria': row[6]
                }
                respuesta.append(dato)
            return respuesta
        else:
            raise HTTPException(status_code=404, detail="No hay sitios en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.get("/explora/{id_explora}", status_code=status.HTTP_200_OK, summary="Endpoint para buscar un sitio en la bd", tags=['Explora'])
def detalle_sitio(id_explora: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    try:
        # Consulta para obtener el sitio de la tabla explora
        query_explora = "SELECT * FROM explora WHERE id_explora = %s"
        cursor.execute(query_explora, (id_explora,))
        datos_explora = cursor.fetchone()

        if datos_explora:
            # Consulta para obtener la longitud y latitud de la tabla ubicaciones basada en el nombre del sitio
            query_ubicaciones = "SELECT latitud, longitud  FROM ubicaciones WHERE lugar = %s"
            cursor.execute(query_ubicaciones, (datos_explora[1],))
            datos_ubicaciones = cursor.fetchone()

            if datos_ubicaciones:
                respuesta = {
                    'id_explora': datos_explora[0],
                    'nombre_sitio': datos_explora[1],
                    'direccion': datos_explora[2],
                    'descripcion': datos_explora[3],
                    'imagen': datos_explora[4],
                    'ruta': datos_explora[5],
                    'longitud': datos_ubicaciones[0],
                    'latitud': datos_ubicaciones[1]
                }
                return respuesta
            else:
                raise HTTPException(status_code=404, detail="No existe la ubicación para el sitio en la Base de datos")
        else:
            raise HTTPException(status_code=404, detail="No existe ese sitio en la Base de datos")
    finally:
        cursor.close()
        connection.close()

@app.post("/explora/crear", status_code=status.HTTP_201_CREATED, summary="Endpoint para crear un sitio en Explora", tags=['Explora'])
async def crear_sitio(
    nombre_sitio: str = Form(...),
    direccion: str = Form(None),
    descripcion: str = Form(...),
    file: UploadFile = File(...),
    categoria: str = Form(...),
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
         # Guardar temporalmente el archivo
        file_location = f"static/temp/{file.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)


        # Validar el tamaño de la imagen
        try:
            with Image.open(file_location) as img:
                if img.size < (200, 200):
                    raise HTTPException(status_code=400, detail="La imagen debe tener al menos 200x200 píxeles")
                elif img.size > (9000, 9000):
                    raise HTTPException(status_code=400, detail="La imagen debe tener como máximo 9000x9000 píxeles")
        except Exception as e:
            raise HTTPException(status_code=400, detail="Archivo de imagen inválido")


        # Si no se proporciona una dirección, buscarla usando el nombre del sitio
        if not direccion:
            query_ubicacion = "SELECT latitud, longitud FROM ubicaciones WHERE lugar = %s;"
            cursor.execute(query_ubicacion, (nombre_sitio,))
            datos = cursor.fetchone()
            if datos:
                latitud, longitud = datos
                coordenadas = f"{latitud}, {longitud}"
                location = geolocator.reverse(coordenadas)
                if location:
                    direccion = location.address
                else:
                    raise HTTPException(status_code=404, detail="No se pudo obtener la dirección a partir de las coordenadas")
            else:
                raise HTTPException(status_code=404, detail="No existe esa ubicación en la Base de datos")
            
        # Mover el archivo al directorio final
        final_location = f"static/images/explora/{file.filename}"
        shutil.move(file_location, final_location)

         # Subir la imagen al servidor FTP con la ruta completa
        ftp_path = "/static/images/explora"
        with ftp_connect() as ftp:
            create_ftp_directory(ftp, ftp_path)
            with open(final_location, 'rb') as f:
                ftp.storbinary(f"STOR {ftp_path}/{file.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
        base_url = "https://test.santiagotulantepec.com"
        imagen_url = f"{base_url}{ftp_path}/{file.filename}"

        # Insertar el nuevo sitio en la base de datos
        query = "INSERT INTO explora (nombre_sitio, direccion, descripcion, imagen, ruta, categoria) VALUES (%s, %s, %s, %s, %s, %s)"
        sitio_data = (nombre_sitio, direccion, descripcion, file.filename, imagen_url, categoria)
        cursor.execute(query, sitio_data)
        connection.commit()

        return JSONResponse(content={
            'message': 'Sitio creado exitosamente',
            'data': {
                'nombre_sitio': nombre_sitio,
                'direccion': direccion,
                'descripcion': descripcion,
                'imagen': file.filename,
                'ruta': imagen_url,
                'categoria': categoria
            }
        })

    except mysql.connector.Error as err:
        print(f"Error al insertar sitio en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al crear sitio")
    except Exception as e:
        print(f"Error inesperado: {e}")
        raise HTTPException(status_code=500, detail="Error inesperado al procesar la solicitud")
    finally:
        cursor.close()
        connection.close()

@app.put("/explora/editar/{id_explora}", status_code=status.HTTP_200_OK, summary="Endpoint para editar un sitio en Explora", tags=['Explora'])
async def editar_contacto(
    id_explora: int,
    descripcion: str = Form(None),
    imagen: UploadFile = File(None),
    categoria: str = Form(None)
):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Procesar la imagen si se proporciona
        if imagen:
            # Guardar la imagen en una ubicación temporal
            file_location = f"static/temp/{imagen.filename}"
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(imagen.file, buffer)

            # Mover la imagen a la ubicación final y asegurarse de que sea válida
            final_location = f"static/images/explora/{imagen.filename}"
            shutil.move(file_location, final_location)

             # Subir la imagen al servidor FTP con la ruta completa
            ftp_path = "/static/images/explora"
            with ftp_connect() as ftp:
                create_ftp_directory(ftp, ftp_path)
                with open(final_location, 'rb') as f:
                    ftp.storbinary(f"STOR {ftp_path}/{imagen.filename}", f)

            # Generar la URL pública del archivo en el servidor FTP
            base_url = "https://test.santiagotulantepec.com"
            imagen_url = f"{base_url}{ftp_path}/{imagen.filename}"
            
            # Actualizar la base de datos con la información de la imagen
            query = "UPDATE explora SET descripcion = %s, categoria = %s, imagen = %s, ruta = %s WHERE id_explora = %s"
            contacto_data = (descripcion, categoria, imagen.filename, imagen_url, id_explora)
            cursor.execute(query, contacto_data)
            connection.commit()

            return {
                'id_explora': id_explora,
                'descripcion': descripcion,
                'categoria': categoria,
                'imagen': imagen.filename,
                'ruta': imagen_url
            }
        else:
            # Si no se proporciona una imagen, actualizar solo los campos de texto
            query = "UPDATE contactos SET descripcion = %s, categoria = %s WHERE id_explora = %s"
            contacto_data = (descripcion, categoria, id_explora)
            cursor.execute(query, contacto_data)
            connection.commit()

            return JSONResponse(content={
                'id_explora': id_explora,
                'descripcion': descripcion,
                'categoria': categoria,
                'imagen': "No se cambió la imagen"
            })
    except mysql.connector.Error as err:
        print(f"Error al actualizar contacto en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al actualizar contacto")
    finally:
        cursor.close()
        connection.close()

@app.delete("/explora/borrar/{id_explora}", status_code=status.HTTP_200_OK, summary="Endpoint para borrar un sitio en Explora", tags=['Explora'])
async def borrar_sitio(id_explora: int):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Obtener la información del sitio a borrar para eliminar la imagen del sistema de archivos
        query_select = "SELECT imagen FROM explora WHERE id_explora = %s"
        cursor.execute(query_select, (id_explora,))
        sitio = cursor.fetchone()
        if not sitio:
            raise HTTPException(status_code=404, detail="Sitio no encontrado")

        imagen = sitio[0]

        # Conectar al servidor FTP y eliminar el archivo
        ftp = ftp_connect()
        ftp_path = "/static/images/funcionarios"
        file_location = f"{ftp_path}/{imagen}"

        try:
            ftp.delete(file_location)
        except Exception as e:
            print(f"Error al eliminar archivo del servidor FTP: {e}")

        finally:
            ftp.quit()

        # Eliminar el sitio de la base de datos
        query_delete = "DELETE FROM explora WHERE id_explora = %s"
        cursor.execute(query_delete, (id_explora,))
        connection.commit()

        return JSONResponse(content={
            'message': 'Sitio borrado exitosamente'
        })

    except mysql.connector.Error as err:
        print(f"Error al borrar sitio en la base de datos: {err}")
        raise HTTPException(status_code=500, detail="Error interno al borrar sitio")
    except Exception as e:
        print(f"Error inesperado: {e}")
        raise HTTPException(status_code=500, detail="Error inesperado al procesar la solicitud")
    finally:
        cursor.close()
        connection.close()