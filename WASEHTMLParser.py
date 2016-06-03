import sys
if sys.version_info[0] == 2:
    from HTMLParser import HTMLParser
else:
    from html.parser import HTMLParser

# extract values from attrList of attributes whose name is contained in attrNames
def add_attrs(attrNames, attrList):
    return [a[1] for a in filter(lambda attr: attr[0] in attrNames, attrList)]

class WASEHTMLParser(HTMLParser, object):
    def reset(self):
        self.doctype = set()
        self.base = set()
        self.stylesheets = set()
        self.frames = set()
        self.scripts = set()
        self.links = set()
        self.images = set()
        self.audio = set()
        self.video = set()
        self.objects = set()
        self.formactions = set()
        super(WASEHTMLParser, self).reset()

    def handle_decl(self, decl):
        self.doctype.add(decl)

    def handle_starttag(self, tag, attrs):
        if tag == "iframe":
            self.frames = self.frames.union(add_attrs(["src"], attrs))
        elif tag == "base":
            self.base = self.base.union(add_attrs(["href"], attrs))
        elif tag == "link" and "rel" in attrs and attrs["rel"] == "stylesheet":
            self.stylesheets = self.stylesheets.union(add_attrs(["href"], attrs))
        elif tag == "script":
            self.scripts = self.scripts.union(add_attrs(["src"], attrs))
        elif tag == "a" or tag == "area":
            self.links = self.links.union(add_attrs(["href"], attrs))
        elif tag == "img" or tag == "input":
            self.images = self.images.union(add_attrs(["src"], attrs))
        elif tag == "svg" or tag == "image":
            self.images = self.images.union(add_attrs(["href", "xlink:href"], attrs))
        elif tag == "audio":
            self.audio = self.audio.union(add_attrs(["src"], attrs))
        elif tag == "video":
            self.video = self.video.union(add_attrs(["src"], attrs))
        elif tag == "object":
            self.objects = self.objects.union(add_attrs(["data"], attrs))
        elif tag == "embed":
            self.objects = self.objects.union(add_attrs(["src"], attrs))
        elif tag == "applet":
            self.objects = self.objects.union(add_attrs(["code"], attrs))
        elif tag == "form":
            self.formactions = self.formactions.union(add_attrs(["action"], attrs))
        elif tag == "input" or tag == "button":
            self.formactions = self.formactions.union(add_attrs(["formaction"], attrs))
        else:
            return

    def close(self):
        self.extrefs = set()
        self.extrefs.update(
                self.stylesheets,
                self.frames,
                self.scripts,
                self.links,
                self.images,
                self.audio,
                self.video,
                self.objects,
                self.formactions
                )
        return super(WASEHTMLParser, self).close()
