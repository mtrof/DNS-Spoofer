# DNS-Spoofer
## Инструмент для перехвата DNS-трафика жертвы в локальной сети
Проводит атаку посредника (MITM) между жертвой и шлюзом сети, используя:
1) ARP-spoofing: подмена ARP-таблиц у жертвы и шлюза
2) DNS-spoofing: перехват и подмена DNS-ответов
3) Запуск локального веб-сервера для предоставления фальшивой страницы жертве

Использование (запускать от имени администратора):
```
python3 main.py victim_ip gateway_ip [interface_name]
```

P. S.

Для работы веб-сервера необходимо создать самоподписанный сертификат:
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
```
Файлы key.pem и cert.pem положить в папку certificate