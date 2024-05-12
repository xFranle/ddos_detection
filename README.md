# Detección Proactiva de Ataques DDoS en Tiempo Real

El proyecto se centra en la detección proactiva de ataques DDoS, un tipo de amenaza cibernética que puede paralizar las operaciones de una red al inundarla con un gran volumen de tráfico malicioso. Utilizando Python y varias bibliotecas especializadas, hice un sistema de detección de ataques DDoS que analiza el tráfico de red en busca de patrones anómalos y activa alertas automáticas para una respuesta inmediata.

## Características Destacadas:
- **Análisis en Tiempo Real:** El sistema monitorea constantemente el tráfico de red en busca de signos de actividad sospechosa, permitiendo una detección rápida y eficiente de posibles ataques DDoS.
- **Umbral de Alerta Ajustable:** Los administradores pueden configurar fácilmente el umbral de tráfico para activar alertas, lo que proporciona flexibilidad para adaptarse a diferentes entornos de red y niveles de actividad.
- **Integración con Correo Electrónico y Firewall:** Se envían alertas automáticas por correo electrónico cuando se detecta un posible ataque DDoS, y se ofrece la opción de bloquear direcciones IP maliciosas en el firewall para mitigar el impacto del ataque.
- **Seguridad de Contraseñas:** Las contraseñas y otros datos sensibles se manejan de manera segura utilizando variables de entorno, siguiendo las mejores prácticas de seguridad de la información.

## Tecnologías Utilizadas:
- *Python:* Lenguaje de programación principal para el desarrollo del proyecto.
- *PyShark:* Biblioteca para la captura y análisis de tráfico de red.
- *Paramiko:* Biblioteca para la comunicación SSH utilizada en el bloqueo de direcciones IP en el firewall.
- *smtplib:* Módulo para el envío de correos electrónicos de alerta.
