from plugin import BasePlugin

from poezio.config import config

from Crypto.Cipher import AES
from Crypto import Random

import base64
import re

from lima_gold import encryptim

encryptim.register()

MODE_PLAIN = 0
MODE_GOLD = 1
MODE_STEALTH = 2

class Plugin(BasePlugin):

    def init(self):
        self.encrypted_message_info = "[Diese Nachricht ist nur für Lima-Gold-Mitglieder " \
                        "lesbar. Mehr auf lima-city.de/gold]"
        self.encrypted_link_info = "[Dieser Link ist nur für Lima-Gold-Mitglieder lesbar. " \
                        "Mehr auf lima-city.de/gold]"
        self.encrypted_section_info = "[Dieser Teil der Nachricht ist nur für " \
                        "Lima-Gold-Mitglieder lesbar. Mehr auf lima-city.de/gold]"

        self.url_regex = re.compile(r'(https?|ftps?|ssh|sftp|irc|xmpp)://([a-zA-Z0-9]+)')

        self.api.add_event_handler("muc_msg", self.on_muc_message)
        self.api.add_event_handler("muc_say", self.on_muc_say)
        self.api.add_command("q", self.stealth, "Send a stealthy message")
        self.api.add_command("e", self.gold, "Send a lima-gold message")
        self.api.add_command("es", self.partly_gold, "Send a message that is encrypted after the first occurence of »$«")
        self.api.add_command("el", self.link_gold, "Send a message that is encrypted after the first occurence of a link")
        self.api.add_command("stealth", self.stealth_mode, "Send a stealthy message")
        self.api.add_command("encrypt", self.gold_mode, "Send a lima-gold message")
        self.api.add_command("plain", self.plain_mode, "Send a lima-gold message")

        self.key = config.get("key").encode('utf-8')
        length = 32 - (len(self.key) % 32)
        self.key += bytes([length]) * length
        self.encrypt = True

        self.mode = MODE_PLAIN

        self.core.xmpp.register_plugin('encrypt-im')

    def stealth_mode(self, msg):
        self.mode = MODE_STEALTH

    def gold_mode(self, msg):
        self.mode = MODE_GOLD

    def plain_mode(self, msg):
        self.mode = MODE_PLAIN

    def encode(self, msg):
        data = msg.encode('utf-8')
        iv = Random.new().read(AES.block_size)
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        length = 16 - (len(data) % 16)
        data += bytes([length]) * length
        enc = aes.encrypt(data)
        return base64.b64encode(iv + enc).decode('ascii')

    def decode(self, msg):
        raw = base64.b64decode(msg)
        iv = raw[0:AES.block_size]
        msg = raw[AES.block_size:]
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        data = aes.decrypt(msg)
        return data[:-data[-1]].decode('utf-8')

    def on_muc_message(self, msg, tab):
        if len(msg["encrypted"]["content"]) != 0:
            if self.key is not None:
                data = msg["encrypted"]["content"]
                try:
                    body = self.decode(data)
                    # TODO: Find better way to indicate a stealth message than changing the body
                    if len(body) > 0:
                        msg["body"] = "$>> %s" % body
                    else:
                        msg["body"] = "** empty stealth message or wrong key **"
                except Exception as e:
                    self.api.information("exception while decoding: %s" % e)

        if len(msg["body"]) > 0 and self.key is not None:
            try:
                XHTML_NS = 'http://www.w3.org/1999/xhtml'
                span = msg['html'].xml.find('.//{%s}span[@data]' %
                        XHTML_NS)
                if span is not None:
                    # TODO: Find better way to indicate a gold message than changing the body
                    data = span.attrib.get('data')
                    msg['body'] = "#>> %s" % self.decode(data)
            except Exception as e:
                self.api.information("exception while decoding: %s" % e)

    def on_muc_say(self, msg, tab):
        # the body = None method is ugly - but works. It ain't stupid if it works!
        if self.mode == MODE_GOLD:
            self.gold(msg["body"])
            msg["body"] = None
        elif self.mode == MODE_STEALTH:
            self.stealth(msg["body"])
            msg["body"] = None

    def link_gold(self, msg):
        text = msg.strip()
        match = self.url_regex.search(text)
        if match is not None:
            msg = text[:match.start()]
            url = text[match.start():]
            plain_msg = "%s %s" % (msg.strip(), self.encrypted_link_info)
            cipher_msg = "%s%s" % (msg, url)
            self.send_gold(plain_msg, cipher_msg)
        else:
            self.core.xmpp.send_message(mto=self.api.current_tab().name, mbody=msg)

    def partly_gold(self, msg):
        text = msg[4:].strip()
        plain_text = ""
        cipher_text = ""
        cipher = False
        escape = False
        for c in msg:
            if cipher:
                cipher_text += c
            elif escape:
                escape = False
                plain_text += c
            elif c == "\\":
                escape = True
            elif c == "$":
                cipher = True
            else:
                plain_text += c
        plain_msg = "%s %s" % (plain_text.strip(), self.encrypted_section_info)
        cipher_msg = "%s%s" % (plain_text, cipher_text)
        self.send_gold(plain_msg, cipher_msg)

    def gold(self, msg):
        self.send_gold(self.encrypted_message_info, msg)

    def send_gold(self, plain, cipher):
        html = '<span data="%s">%s</span>' % (self.encode(cipher),
                plain)
        tab = self.api.current_tab()
        self.core.xmpp.send_message(mto=tab.name,
                mbody=plain, mhtml=html,
                mtype='groupchat')

    def stealth(self, msg):
        message = self.core.xmpp.Message(sto=self.api.current_tab().name,
                stype='groupchat', sfrom=None)
        message['encrypted']['content'] = self.encode(msg)
        message.send()
