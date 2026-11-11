const API_URL = "http://127.0.0.1:8000/api";

// 1. REGISTRAR USUARIO
const formRegister = document.getElementById("form-register");
if (formRegister) {
  formRegister.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("reg-email").value;
    const password = document.getElementById("reg-password").value;

    try {
      const res = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok) {
        alert("¡Usuario registrado con éxito en PostgreSQL!");
        document.getElementById("secret-key").innerText = data.secretBase32;
        document.getElementById("qr-info").style.display = "block";
        formRegister.reset();
      } else {
        alert(`Error en registro: ${data.detail}`);
      }
    } catch (err) {
      alert("Error de conexión. Asegúrate de tener FastAPI activo en http://127.0.0.1:8000");
    }
  });
}

// 2. INICIAR SESIÓN - PASO 1
const formLoginStep1 = document.getElementById("form-login-step1");
if (formLoginStep1) {
  formLoginStep1.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("login-email").value;
    const password = document.getElementById("login-password").value;

    try {
      const res = await fetch(`${API_URL}/login/step1`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (res.ok) {
        sessionStorage.setItem("temp_userId", data.userId);
        alert("Paso 1 correcto. Ingresa tu código de 6 dígitos del autenticador.");
        
        document.getElementById("login-step1-container").style.display = "none";
        document.getElementById("login-step2-container").style.display = "block";
      } else {
        alert(`Error de autenticación: ${data.detail}`);
      }
    } catch (err) {
      alert("Error de conexión con el servidor backend.");
    }
  });
}

// 3. INICIAR SESIÓN - PASO 2 (2FA)
const formLoginStep2 = document.getElementById("form-login-step2");
if (formLoginStep2) {
  formLoginStep2.addEventListener("submit", async (e) => {
    e.preventDefault();

    const userId = parseInt(sessionStorage.getItem("temp_userId"));
    const token = document.getElementById("totp-token").value;

    try {
      const res = await fetch(`${API_URL}/login/step2`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, token })
      });

      const data = await res.json();

      if (res.ok) {
        alert("¡Inicio de sesión 2FA exitoso! Bienvenido.");
        sessionStorage.removeItem("temp_userId");
      } else {
        alert(`Código 2FA incorrecto: ${data.detail}`);
      }
    } catch (err) {
      alert("Error de conexión con el servidor backend.");
    }
  });
}