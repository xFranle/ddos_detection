import pyshark
import logging
import paramiko
import smtplib
from email.mime.text import MIMEText
import os

def configurar_logger():
    """
    Configura el registro de eventos en un archivo de registro.
    """
    logging.basicConfig(filename='detector_ataques.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def enviar_alerta_email(mensaje):
    """
    Envía una alerta por correo electrónico.
    
    :parametro mensaje: Mensaje de la alerta.
    """
    # Obtener credenciales y configuración de las variables de entorno
    servidor_smtp = os.environ.get('SERVIDOR_SMTP')
    puerto_smtp = os.environ.get('PUERTO_SMTP')
    correo_emisor = os.environ.get('CORREO_EMISOR')
    contraseña_emisor = os.environ.get('CONTRASEÑA_EMISOR')
    correo_receptor = os.environ.get('CORREO_RECEPTOR')

    # Crear mensaje de correo electrónico
    mensaje_correo = MIMEText(mensaje, 'plain')
    mensaje_correo['From'] = correo_emisor
    mensaje_correo['To'] = correo_receptor
    mensaje_correo['Subject'] = "Alerta de Seguridad: Detección de Ataque"

    try:
        # Configurar conexión SMTP y enviar correo
        servidor = smtplib.SMTP(servidor_smtp, puerto_smtp)
        servidor.starttls()
        servidor.login(correo_emisor, contraseña_emisor)
        servidor.sendmail(correo_emisor, correo_receptor, mensaje_correo.as_string())
        servidor.quit()
        logging.info("Correo electrónico de alerta enviado exitosamente.")
    except smtplib.SMTPAuthenticationError:
        logging.error("Error de autenticación SMTP al enviar el correo electrónico de alerta.")
    except smtplib.SMTPException as e:
        logging.error("Error SMTP al enviar el correo electrónico de alerta: {}".format(e))

def bloquear_ip_maliciosa(ip):
    """
    Bloquea una dirección IP maliciosa en el firewall.
    
    :parametro ip: Dirección IP maliciosa a bloquear.
    """
    try:
        # Obtener contraseña SSH de la variable de entorno
        contraseña_ssh = os.environ.get('CONTRASEÑA_SSH')
        
        # Configurar conexión SSH al firewall
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname='firewall.example.com', username='tu_usuario', password=contraseña_ssh)

        # Ejecutar comando para agregar regla de bloqueo en el firewall
        comando = f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} drop'"
        _, stderr, _ = ssh_client.exec_command(comando)

        # Verificar resultado de la ejecución del comando
        if stderr.read():
            logging.error(f"No se pudo bloquear la IP {ip}. Error: {stderr.read()}")
        else:
            logging.info(f"IP {ip} bloqueada exitosamente en el firewall.")

        # Cerrar conexión SSH
        ssh_client.close()
    except paramiko.ssh_exception.AuthenticationException:
        logging.error("Error de autenticación SSH al conectar con el firewall.")
    except paramiko.SSHException as e:
        logging.error("Error SSH al conectar con el firewall: {}".format(e))
    except Exception as e:
        logging.error("Error al bloquear la dirección IP maliciosa: {}".format(e))

def detectar_ataque_ddos():
    """
    Detecta un posible ataque DDoS analizando el tráfico de red.
    """
    configurar_logger()
    logging.info("Iniciando captura y análisis de tráfico de red para detectar ataques DDoS...")

    umbral_alerta = 1000  # Umbral de tráfico para activar una alerta de DDoS
    contador_alerta = 0

    try:
        # Iniciar captura de tráfico de red
        cap = pyshark.LiveCapture(interface='eth0')

        for pkt in cap.sniff_continuously():
            # Incrementar contador de paquetes
            contador_alerta += 1

            # Verificar si se supera el umbral de alerta
            if contador_alerta >= umbral_alerta:
                mensaje = "Se ha superado el umbral de alerta. ¡Posible ataque DDoS detectado!"
                enviar_alerta_email(mensaje)
                # Opcional: bloquear la dirección IP maliciosa
                bloquear_ip_maliciosa(pkt.ip.src)
                break

    except pyshark.capture.capture.TSharkCrashException as e:
        logging.error("TShark ha fallado durante la captura de tráfico: {}".format(e))
    except KeyboardInterrupt:
        logging.info("Proceso de detección de ataques DDoS detenido manualmente.")
    except Exception as e:
        logging.error("Error durante la captura y análisis de tráfico de red: {}".format(e))


if __name__ == "__main__":
    detectar_ataque_ddos()
