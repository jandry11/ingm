const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Configuración de la conexión a PostgreSQL
const pool = new Pool({
    user: 'postgres',          // Cambia por tu usuario de PostgreSQL
    host: 'localhost',
    database: 'login_seguro_db',
    password: 'tu_password',   // Cambia por tu contraseña de PostgreSQL
    port: 5432,
});

// 1. ENDPOINT DE REGISTRO
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }

        // Calidad de Software: Hashing seguro con Bcrypt (cost factor 12)
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generar clave secreta para Google Authenticator
        const secret = speakeasy.generateSecret({ name: `AppSegura (${email})` });

        // Guardar en PostgreSQL
        const newUser = await pool.query(
            'INSERT INTO users (email, password_hash, totp_secret) VALUES ($1, $2, $3) RETURNING id',
            [email, hashedPassword, secret.base32]
        );

        res.status(201).json({
            message: 'Usuario registrado con éxito',
            userId: newUser.rows[0].id,
            secretBase32: secret.base32,
            qrCodeUrl: secret.otpauth_url
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 2. ENDPOINT LOGIN PASO 1 (Verifica Credenciales)
app.post('/api/login/step1', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        const genericErrorMsg = 'Credenciales inválidas';
        if (result.rows.length === 0) {
            return res.status(401).json({ error: genericErrorMsg });
        }

        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: genericErrorMsg });
        }

        res.json({
            success: true,
            userId: user.id,
            message: 'Credenciales correctas. Ingrese el código 2FA.'
        });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 3. ENDPOINT LOGIN PASO 2 (Verifica el Código TOTP de 6 dígitos)
app.post('/api/login/step2', async (req, res) => {
    try {
        const { userId, token } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Sesión no válida' });
        }

        const user = result.rows[0];

        const verified = speakeasy.totp.verify({
            secret: user.totp_secret,
            encoding: 'base32',
            token: token,
            window: 1 
        });

        if (!verified) {
            return res.status(400).json({ error: 'Código 2FA incorrecto o expirado' });
        }

        res.json({
            success: true,
            message: '¡Autenticación de dos factores exitosa!',
            token: 'mock-jwt-token-seguro.abc'
        });

    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor backend corriendo en http://localhost:${PORT}`);
});