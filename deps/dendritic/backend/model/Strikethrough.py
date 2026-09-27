from markdown import Extension
from markdown.inlinepatterns import InlineProcessor
from xml.etree import ElementTree as etree


class StrikethroughPattern(InlineProcessor):
    """Reddit-style ``~~text~~`` strikethrough (not part of core markdown)."""

    _STRIKE_REGEXP = r"~~(.+?)~~"

    def __init__(self):
        super().__init__(self._STRIKE_REGEXP)

    def handleMatch(self, match, data):
        element = etree.Element("del")
        element.text = match.group(1)
        return element, match.start(0), match.end(0)


class StrikethroughExtension(Extension):
    def extendMarkdown(self, md):
        md.inlinePatterns.register(StrikethroughPattern(), "strikethrough", 202)
