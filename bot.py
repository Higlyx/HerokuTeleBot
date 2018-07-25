# -*- coding: utf-8 -*-
import config
import telebot
import cherrypy

WEBHOOK_HOST = '209.126.90.135'
WEBHOOK_PORT = 443  # 443, 80, 88 или 8443 (порт должен быть открыт!)
WEBHOOK_LISTEN = '0.0.0.0'  # На некоторых серверах придется указывать такой же IP, что и выше

WEBHOOK_SSL_CERT = './webhook_cert.pem'  # Путь к сертификату
WEBHOOK_SSL_PRIV = './webhook_pkey.pem'  # Путь к приватному ключу

WEBHOOK_URL_BASE = "https://%s:%s" % (WEBHOOK_HOST, WEBHOOK_PORT)
WEBHOOK_URL_PATH = "/%s/" % (config.token)

bot = telebot.TeleBot(config.token)
@bot.message_handler(commands=['webhook','вебхук'])
def webhook():
        bot.send_message(338856893,bot.get_webhook_info())
#Наш вебхук-сервер
class WebhookServer(object):
        @cherrypy.expose
        def index(self):
                if 'content-length' in cherrypy.request.headers and \
                           'content-type' in cherrypy.request.headers and \
                           cherrypy.request.headers['content-type'] == 'application/json':
                        length = int(cherrypy.request.headers['content-length'])
                        json_string = cherrypy.request.body.read(length).decode("utf-8")
                        update = telebot.types.Update.de_json(json_string)
                        #Эта функция обеспечивает проверку входящего сообщения
                        bot.process_new_updates([update])
                        return ''
                else:
                        raise cherrypy.HTTPError(403)

@bot.message_handler(func=lambda message: True, content_types = ['text'])
def echo(message):
        bot.reply_to(message, message.text)
@bot.message_handler(content_types=["text"])
def repeat_all_messages(message): # Название функции не играет никакой роли, в принципе
    bot.send_message(message.chat.id, message.text)

#Снимаем вебхук перед повторной установкой
#bot.remove_webhook()

#Ставим вебхук
#bot.set_webhook(url = WEBHOOK_URL_BASE + WEBHOOK_URL_PATH, certificate = open(WEBHOOK_SSL_CERT, 'r'))


#Указываем настройки cherrypy
cherrypy.config.update({
    'server.socket_host': WEBHOOK_LISTEN,
    'server.socket_port': WEBHOOK_PORT,
    'server.ssl_module': 'builtin',
    'server.ssl_certificate': WEBHOOK_SSL_CERT,
    'server.ssl_private_key': WEBHOOK_SSL_PRIV
})

# Запуск
cherrypy.quickstart(WebhookServer(), WEBHOOK_URL_PATH, {'/': {}})

