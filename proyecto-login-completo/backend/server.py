from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor
import pyotp
import re

# 1. CREAR LA INSTANCIA DE FASTAPI (Debe ir aquí antes de las rutas @app)
app = FastAPI()

# 2. CONFIGURAR CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.com$")

# 3. CONEXIÓN A POSTGRESQL
def get_db():
    try:
        return psycopg2.connect(
            host="localhost",
            database="login_seguro_db",
            user="postgres",
            password="12345",  # Ajusta si tu contraseña de pgAdmin es distinta
            port=5432
        )
    except Exception as e:
        print(f"\n[ERROR DE CONEXIÓN A POSTGRESQL]: {e}\n")
        raise HTTPException(
            status_code=500, 
            detail=f"Fallo de conexión a la BD: {e}"
        )

# 4. MODELOS DE DATOS
class UserAuth(BaseModel):
    email: str
    password: str

class Step2Auth(BaseModel):
    userId: int
    token: str

# 5. RUTAS DE LA API

# --- RUTA DE REGISTRO ---
@app.post("/api/register")
def register(user: UserAuth):
    if not email_regex.match(user.email):
        raise HTTPException(status_code=400, detail="El correo debe terminar en .com")
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="El correo ya está registrado")

        # Recortar contraseña a 72 bytes max para evitar error de bcrypt
        hashed_pw = pwd_context.hash(user.password[:72])
        secret = pyotp.random_base32()

        cursor.execute(
            "INSERT INTO users (email, password_hash, totp_secret) VALUES (%s, %s, %s) RETURNING id",
            (user.email, hashed_pw, secret)
        )
        user_id = cursor.fetchone()["id"]
        conn.commit()

        return {
            "message": "Usuario registrado exitosamente",
            "userId": user_id,
            "secretBase32": secret
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR EN REGISTRO]: {e}\n")
        raise HTTPException(status_code=500, detail=f"Error en el registro: {e}")
    finally:
        cursor.close()
        conn.close()

# --- RUTA DE LOGIN PASO 1 ---
@app.post("/api/login/step1")
def login_step1(user: UserAuth):
    if not email_regex.match(user.email):
        raise HTTPException(status_code=400, detail="El correo debe terminar en .com")

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
        found_user = cursor.fetchone()

        if not found_user or not pwd_context.verify(user.password[:72], found_user["password_hash"]):
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        return {
            "success": True,
            "userId": found_user["id"],
            "message": "Paso 1 correcto. Ingrese su código 2FA"
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"\n[ERROR EN LOGIN PASO 1]: {e}\n")
        raise HTTPException(status_code=500, detail=f"Error en paso 1: {e}")
    finally:
        cursor.close()
        conn.close()

# --- RUTA DE LOGIN PASO 2 ---
@app.post("/api/login/step2")
def login_step2(data: Step2Auth):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("SELECT totp_secret FROM users WHERE id = %s", (data.userId,))
        found_user = cursor.fetchone()

        if not found_user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        totp = pyotp.TOTP(found_user["totp_secret"])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="Código 2FA inválido o expirado")

        return {"message": "¡Inicio de sesión 2FA completado con éxito!"}
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"\n[ERROR EN LOGIN PASO 2]: {e}\n")
        raise HTTPException(status_code=500, detail=f"Error en paso 2: {e}")
    finally:
        cursor.close()
        conn.close()