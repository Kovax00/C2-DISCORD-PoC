# C2-DISCORD-PoC
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
# Contras y pros

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

