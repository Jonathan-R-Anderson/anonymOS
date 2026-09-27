from markdown import Extension
from markdown.inlinepatterns import InlineProcessor
from xml.etree import ElementTree as etree


class SpacingPattern(InlineProcessor):
    _SPACING_REGEXP = r"(\r\n|\n)(?!(\r\n|\n)+)"
    def __init__(self):
        super().__init__(self._SPACING_REGEXP)

    def handleMatch(self, match, data):
        return etree.Element("br"), match.start(0), match.end(0)


class SpacingExtension(Extension):
    def extendMarkdown(self, md):
        spacing = SpacingPattern()
        md.inlinePatterns.register(spacing, "spacing", 5)
