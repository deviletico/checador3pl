# Checador de entradas y salidas

Aplicación web para registrar entradas y salidas del personal con ubicación GPS validada en el servidor. Funciona desde el navegador del celular, sin instalar nada.

## Qué incluye

- **Checada en tiempo real con ubicación.** El celular envía su posición y el servidor calcula la distancia al centro de trabajo. Solo se acepta dentro del radio configurado y con la precisión de GPS requerida. La hora la pone el servidor, no el celular.
- **Registro de personal** con nombre, foto, turno, fecha de ingreso y PIN personal.
- **Turnos de lunes a sábado:**

  | Turno | Entrada | Salida |
  |---|---|---|
  | Matutino | 6:30 | 15:30 |
  | Intermedio | 8:00 | 17:00 |
  | Cierre | 11:00 | 20:00 |

- **Conteo de retardos, faltas y horas trabajadas** por empleado y por periodo.
- **Panel de administración:** tablero del día, reporte con exportación a CSV (abre en Excel), alta y baja de personal, incidencias (festivos, vacaciones, incapacidades, faltas justificadas), correcciones manuales de checadas y ajustes.

## Cómo se calcula

- **Retardo:** entrada posterior a la hora del turno más la tolerancia. La tolerancia inicial es de **10 minutos** (configurable en Ajustes; pon 0 si no quieres tolerancia).
- **Falta:** día laborable (lunes a sábado) sin entrada, a partir de la fecha de ingreso y sin incidencia registrada. El día en curso solo cuenta como falta cuando el turno ya terminó.
- **Horas trabajadas:** de la primera entrada a la salida del mismo día. Si descuentas la comida, indica los minutos en Ajustes (se restan en jornadas de más de 6 h; inicia en 0).
- **Sin salida:** si alguien olvida checar salida, el día cuenta como trabajado con 0 horas y se marca "sin salida". El administrador agrega la salida desde el detalle del empleado, con un motivo.
- **Domingo** no es laborable: no genera faltas y no se puede checar.
- Cada persona registra **una entrada y una salida por día**. Para evitar toques accidentales, se bloquea una segunda checada en menos de un minuto, y la entrada solo se permite hasta 2 horas antes del turno (configurable).

## Probarla en tu computadora

Requiere Node 18 o superior.

```bash
npm install
ADMIN_PASSWORD="elige-una-clave" npm start
```

Abre `http://localhost:3000`. El panel está en `http://localhost:3000/admin`.

## Primer uso

1. Entra a `/admin` con tu contraseña y ve a **Ajustes**. Estando en el centro de trabajo, abre esa pantalla desde tu celular y toca **Usar mi ubicación actual**, o captura latitud y longitud a mano. Revisa el radio (inicia en 150 m) y la precisión máxima del GPS (inicia en 80 m).
2. En **Personal**, da de alta a cada persona con foto, turno, fecha de ingreso y un PIN de 4 a 6 dígitos.
3. Comparte con el personal la dirección principal del sitio. Cada quien elige su nombre, escribe su PIN y toca **Registrar entrada** o **Registrar salida**. La sesión se mantiene en su celular.

## Publicarla para que la use el personal

El GPS del navegador solo funciona en sitios con **HTTPS**, así que necesitas publicarla en un servicio que lo incluya (cualquier hosting con Node.js sirve). Lo necesario:

- Comando de instalación `npm install` y de inicio `npm start`.
- Variables de entorno:

  | Variable | Para qué sirve |
  |---|---|
  | `ADMIN_PASSWORD` | Contraseña del panel. **Obligatoria** cuando `NODE_ENV=production`. |
  | `NODE_ENV` | Usa `production`. |
  | `DATA_DIR` | Carpeta donde se guardan la base de datos y las fotos. Debe estar en un **disco persistente**. |
  | `SESSION_SECRET` | Opcional. Si no la defines, se genera y se guarda en `DATA_DIR`. |
  | `APP_TZ` | Zona horaria del centro de trabajo. Por defecto `America/Mexico_City`. |
  | `PORT` | Puerto; casi todos los servicios lo asignan solos. |

- **Respalda `DATA_DIR`** con regularidad: ahí están todas las checadas.

## Límites que conviene conocer

- **El GPS se puede falsificar.** Un celular con una app de ubicación falsa puede engañar a cualquier checador web. La validación en servidor, el PIN personal, la exigencia de una lectura reciente y precisa, y la distancia registrada en cada checada (visible en el detalle del empleado) reducen el riesgo, pero no lo eliminan.
- **Datos personales.** La aplicación guarda ubicación, fotos y horarios del personal. Confirma con tu área legal el aviso de privacidad que corresponda.
- Los PIN se guardan con hash, así que nadie puede consultarlos. Si alguien lo olvida, edita a la persona y asígnale uno nuevo.
- Tras 5 intentos fallidos de acceso se bloquea ese acceso por 10 minutos.

## Pruebas

```bash
npm test
```

Incluyen la lógica de retardos, faltas y horas, y un recorrido completo del servidor con reloj y ubicaciones simuladas.

## Estructura

```
server.js        servidor y API
lib/calc.js      turnos, retardos, faltas, horas y distancia
public/          pantalla del empleado (index.html) y panel (admin.html)
test/            pruebas automáticas
data/            base de datos y fotos (se crea sola; no se sube a git)
```
