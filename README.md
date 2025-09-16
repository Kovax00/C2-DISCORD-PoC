# C2-DISCORD-PoC

<img width="1839" height="987" alt="image" src="https://github.com/user-attachments/assets/8ded959e-cbb7-4c97-96e4-cd63bd3ceb8a" />

Creación del c2 (solo windows) mediante un servidor de discord el cliente cuenta con sus módulos integrados tales como:

* COMANDOS en cmd
* Persistencia con keys
* Escalado de privilegios (metodo ahogamiento)
* keyloagger
* Audio Logger
* Upload/Download | Forzado de descarga carpetas pesadas
* Screenshot
* Ransomware (chacha20)
* Cambio de fondo de pantalla
* campuradora de webcam
---
### Contras y pros

PROS:
* Infraestructura gratuita: no necesitas montar un servidor dedicado, usas la API y servidores de Discord.
* Dificultad de detección: el tráfico se camufla como tráfico legítimo hacia Discord (HTTPS, cifrado TLS).
* Facilidad de uso: solo gestionas bots y comandos en un canal, sin necesidad de programar sockets complejos.
* Persistencia en logs: los resultados de comandos, archivos y datos quedan almacenados en el canal.
* Compatibilidad multiplataforma: clientes C2 pueden comunicarse desde Windows, Linux o incluso móviles.

CONTRAS:
* Limitaciones de la API: tamaño máximo de archivos (~8 MB free, más con Nitro), rate limits estrictos.
* Dependencia de terceros: si Discord detecta actividad sospechosa, puede banear el bot y cortar el C2.
* Menos control de infraestructura: no tienes acceso a bajo nivel como en un C2 propio (no puedes tunelar protocolos arbitrarios).
* Menor sigilo en entornos corporativos: algunos proxies/firewalls bloquean Discord en redes empresariales.
* Escalabilidad limitada: no es óptimo para campañas grandes o múltiples agentes, solo para labs/PoC.
---
### bot

El bot actúa como un C2 sobre la API de Discord: autentica al operador, mantiene un canal de control para recibir órdenes y enviar resultados (mensajes y archivos), y ejecuta procesos locales para ejecutar comandos y exfiltrar salidas. Internamente incluye módulos de recolección (keylogging a fichero, capturas de pantalla, foto por webcam y grabación de audio en hilo), capacidades de lectura/descifrado de datos de navegadores para extraer credenciales y cookies, mecanismos de persistencia y elevación (entradas en registro y solicitud de permisos elevados), un motor de cifrado/descifrado de ficheros basado en ChaCha20+HMAC para acciones tipo ransomware, y rutinas para bloquear la UI (reproducción en fullscreen, bloqueo de input e inyección de texto). Además gestiona empaquetado/exfiltración de archivos y limpieza/gestión de mensajes en el canal.
<img width="725" height="141" alt="image" src="https://github.com/user-attachments/assets/e8f23296-0174-49df-a354-4123cbbfd5ca" />
<img width="735" height="167" alt="image" src="https://github.com/user-attachments/assets/acd60398-09cd-4d52-a0f6-d181b7b06ee2" />

---
### Aclaración  

El PoC no esta creado con la finalidad de mandarlo a terreno ya que fallaria en muchos aspectos del OPSEC, esta creado solo para fines de estudio, si te gusta mi trabajo puedes donarme un cafecito y mantener una charla conmigo en alguna de mis redes sociales.

TIKTOK: kovax00 DISCORD: .cryingdemon


---
### Fscriptkids

Codigo base subido intencionalmente para evitar el mal uso de este.
<img width="1764" height="771" alt="image" src="https://github.com/user-attachments/assets/77b4a6bf-b170-4b73-ac2b-e17122684903" />

---
