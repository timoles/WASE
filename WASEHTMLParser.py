from HTMLParser import HTMLParser

class WASEHTMLParser(HTMLParser, object):
    def reset(self):
        self.doctype = set()
        self.frames = set()
        self.scripts = set()
        super(WASEHTMLParser, self).reset()

    def handle_decl(self, decl):
        self.doctype.add(decl)

    def handle_starttag(self, tag, attrs):
        target = None
        if tag == "iframe":
            target = self.frames
        elif tag == "script":
            target = self.scripts
        else:
            return

        for attr in attrs:
            if attr[0] == "src":
                target.add(attr[1])
