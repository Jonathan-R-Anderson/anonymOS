from markdown import Extension
from markdown.inlinepatterns import InlineProcessor
from xml.etree import ElementTree as etree


class SpoilerPattern(InlineProcessor):
    _SPOILER_REGEXP = r"\|\|(.+)\|\|"
    def __init__(self):
        super().__init__(self._SPOILER_REGEXP)

    def handleMatch(self, match, data):
        spoiler = etree.Element("span")
        spoiler.text = match.group(1)
        spoiler.attrib["class"] = "spoiler"
        return spoiler, match.start(0), match.end(0)


class SpoilerExtension(Extension):
    def extendMarkdown(self, md):
        spoiler = SpoilerPattern()
        md.inlinePatterns.register(spoiler, "spoiler", 200)
