from plugin import BasePlugin
from poezio.xhtml import clean_text
from poezio import common
from poezio import tabs
from poezio import xhtml
from poezio.config import config

from collections import namedtuple

import codecs
import random
import re

from simple_encodings import mono

class Plugin(BasePlugin):
    def init(self):
        self.key = config.get("key").encode('utf-8')
        length = 32 - (len(self.key) % 32)
        self.key += bytes([length]) * length

        self.dicts = {}
        self.german_frequency = { 'a': 6.516,
                                  'b': 1.886,
                                  'c': 2.732,
                                  'd': 5.076,
                                  'e': 16.396,
                                  'f': 1.656,
                                  'g': 3.009,
                                  'h': 4.577,
                                  'i': 6.550,
                                  'j': 0.268,
                                  'k': 1.417,
                                  'l': 3.437,
                                  'm': 2.534,
                                  'n': 9.776,
                                  'o': 2.594,
                                  'p': 0.670,
                                  'q': 0.018,
                                  'r': 7.003,
                                  's': 7.270,
                                  't': 6.154,
                                  'u': 4.166,
                                  'v': 0.846,
                                  'w': 1.921,
                                  'x': 0.034,
                                  'y': 0.039,
                                  'z': 1.134,
                                  'ä': 0.578,
                                  'ü': 0.995,
                                  'ö': 0.443,
                                  'ß': 0.307 }

        self.api.add_command("rot", self.command_rot, "rot n encodes the given message")
        self.api.add_command("bin", self.command_bin, "bin")
        self.api.add_command("hex", self.command_hex, "hex")
        self.api.add_command("enc", self.command_enc, "enc")
        self.api.add_command('rot_decode', self.command_rot_decode,
                    usage='<message>',
                    help='Decode the message you typed if it exists.',
                    short='Decode a message.',
                    completion=self.message_completion)
        self.api.add_command("mono_crack", self.command_mono_crack, usage="<message>",
                    help="mono decode", short="decode", completion=self.message_completion)
        self.api.add_command("bin_decode", self.command_bin_decode, usage="<message>",
                    help="binary decode", short='binary', completion=self.message_completion)
        self.api.add_command("crack", self.command_crack, usage="<message>",
                    help="binary decode", short='binary', completion=self.message_completion)

        self.api.add_event_handler("muc_msg", self.muc_message)

        self.get_dict("de")

    strip_regex = re.compile(r"[:\s-]")
    bits_regex = re.compile(r"^[01\s]+$")
    hex_regex = re.compile(r"^[0-9a-fA-F]+$")
    def muc_message(self, msg, tab):
        body = text = xhtml.get_body_from_message_stanza(msg, key=self.key)

        if text:
            (text, decoding) = self.crack(text)
            if text is not None and len(text) > 0 and text is not body:
                tab.add_message("%s%s" % (decoding, text))

    def command_rot(self, msg):
        args = msg.split(' ')
        n = args[0]
        if n.isdigit():
            self.core.send_message(self.rotn(msg[len(n) + 1:], int(n)))
        else:
            self.core.send_message(self.rotn(msg, random.randrange(1, 26)))

    def command_bin(self, msg):
        self.core.send_message(self.bin(msg))

    def command_hex(self, msg):
        self.core.send_message(self.hex(msg))

    def command_enc(self, msg):
        encodings = msg.split(' ')[0]
        msg = msg[len(encodings) + 1:]

        if 'r' in encodings:
            msg = self.rotn(msg, random.randrange(1, 26))
        if 'b' in encodings:
            msg = self.bin(msg)
        if 'h' in encodings:
            msg = self.hex(msg)

        self.core.send_message(msg)

    Result = namedtuple("Result", ["n", "text", "error"])
    def command_rot_decode(self, msg):
        args = msg.split(' ')
        n = args[0]
        if n.isdigit():
            self.api.information(self.rotn(msg[len(n) + 1:], 26 - int(n)))
        else:
            res = self.rot_crack(msg)
            if res:
                self.api.information("rot(%d): %s" % (res.n, res.text))

    def command_bin_decode(self, msg):
        self.api.information("binary: %s" % self.bin_decode(msg))

    def command_mono_crack(self, text):
        translations = mono.crack(text, "de", iterations=100)

        def translate(c, trans):
            l = c.lower()
            if l in trans:
                return trans[l] if l == c else trans[l].upper()
            return c

        for trans in translations:
            out = "".join([ translate(c, trans) for c in text ])
            self.api.information(out)

    def command_crack(self, msg):
        (text, decoding) = self.crack(msg)
        self.api.information("%s%s" % (decoding, text))

    def crack(self, text):
        stripped = self.strip_regex.sub("", text.strip('" '))
        decoding = ""

        is_bin = lambda x: self.bits_regex.match(x) is not None
        is_hex = lambda x: self.hex_regex.match(x) is not None
        while is_bin(stripped) or is_hex(stripped):
            if is_bin(stripped):
                text = self.bin_decode(stripped)
                decoding = "%sbinary: " % decoding
            elif is_hex(stripped):
                text = self.hex_decode(stripped)
                decoding = "%shex: " % decoding
            stripped = self.strip_regex.sub("", text)

        if len(text) > 0 and not self.is_german(text):
            res = self.rot_crack(text, True)
            if res:
                text = res.text
                decoding = "%srot(%d): " % (decoding, res.n)
        return (text, decoding)

    def rot_crack(self, msg, only_exact=False):
        frequencies = lambda text: { l: text.count(l) / len(text) for l in set(text.lower()) }
        cost = lambda f1, f2: sum([(f - f2[c]) ** 2 for (c, f) in f1.items() if c in f2]) / len(f1)

        c = { cost(frequencies(self.rotn(msg, n)), self.german_frequency): n for n in range(0, 26) }
        candidates = sorted(c.keys())
        results = [ self.Result(26 - c[i], self.rotn(msg, c[i]), i) for i in candidates ]
        for result in results:
            if self.is_german(result.text):
                return result
        if only_exact:
            return None
        return results[0]

    def bin_decode(self, text):
        if len(text) % 8 == 0:
            return "".join([ chr(c) for c in [ int(text[i:i + 8], 2) for i in range(0, len(text), 8) ] ])
        return None

    def hex_decode(self, text):
        if len(text) % 2 == 0:
            return "".join([ chr(c) for c in [ int(text[i:i + 2], 16) for i in range(0, len(text), 2) ] ])
        return None

    def is_german(self, msg):
        min_word_length = 3
        ascii_only = re.compile(r"\W")
        def get_words(text):
            return [ w.strip() for w in ascii_only.sub(" ", text).split(" ")
                    if len(w.strip()) >= min_word_length ]
        d = self.get_dict("de")

        words = get_words(msg)
        threshold = 0.5 if len(words) > 2 else 1
        c = 0
        for (i, word) in enumerate(words):
            if (c + (len(words) - i)) / len(words) < threshold:
                break
            if word.lower() in d:
                c = c + 1
            if c / len(words) >= threshold:
                return True
        return False

    def _read(self, path):
        with open(path) as f:
            return frozenset([ l.strip().lower() for l in f.readlines() \
                    if len(l.strip()) > 0 ])

    def _get_dict(self, lang):
        if lang == "de":
            return self._read("/usr/share/dict/german")
        if lang == "en":
            return self._read("/usr/share/dict/british-english")
        raise ValueError("no dict for language \"%s\"" % lang)

    def get_dict(self, lang):
        if lang in self.dicts:
            return self.dicts[lang]
        self.dicts[lang] = self._get_dict(lang)
        return self.dicts[lang]

    def rotn(self, msg, n):
        res = ""
        for c in msg:
            c = ord(c)
            if c >= ord('a') and c <= ord('z'):
                c = (c - ord('a') + n) % 26 + ord('a')
            elif c >= ord('A') and c <= ord('Z'):
                c = (c - ord('A') + n) % 26 + ord('A')
            res = res + chr(c)
        return res

    def bin(self, msg):
        return "".join([ str(bin(ord(b))[2:]).zfill(8) for b in msg])

    def hex(self, msg):
        return "".join([ str(hex(ord(b))[2:]).zfill(2) for b in msg])


    def message_completion(self, the_input):
        def find_message(txt):
            messages = self.api.get_conversation_messages()
            if not messages:
                return None
            for message in messages[::-1]:
                if clean_text(message.txt) == txt:
                    return message
            return None

        def message_match(msg):
            return input_message.lower() in clean_text(msg.txt).lower()

        messages = self.api.get_conversation_messages()
        if not messages:
            return
        text = the_input.get_text()
        args = common.shell_split(text)
        if not text.endswith(' '):
            input_message = args[-1]
            messages = list(filter(message_match, messages))
        elif len(args) > 1:
            return False
        return the_input.auto_completion([clean_text(msg.txt) for msg in messages[::-1]], '')
