from HTMLParser import HTMLParser

# extract values from attrList of attributes whose name is contained in attrNames
def add_attrs(attrNames, attrList):
    return [a[1] for a in filter(lambda attr: attr[0] in attrNames, attrList)]

class WASEHTMLParser(HTMLParser, object):
    def reset(self):
        self.doctype = set()
        self.frames = set()
        self.scripts = set()
        self.images = set()
        self.objects = set()
        super(WASEHTMLParser, self).reset()

    def handle_decl(self, decl):
        self.doctype.add(decl)

    def handle_starttag(self, tag, attrs):
        if tag == "iframe":
            self.frames = self.frames.union(add_attrs(["src"], attrs))
        elif tag == "script":
            self.scripts = self.scripts.union(add_attrs(["src"], attrs))
        elif tag == "img":
            self.images = self.images.union(add_attrs(["src"], attrs))
        elif tag == "svg" or tag == "image":
            self.images = self.images.union(add_attrs(["href", "xlink:href"], attrs))
        elif tag == "object":
            self.objects = self.objects.union(add_attrs(["data"], attrs))
        elif tag == "embed":
            self.objects = self.objects.union(add_attrs(["src"], attrs))
        elif tag == "applet":
            self.objects = self.objects.union(add_attrs(["code"], attrs))
        else:
            return
