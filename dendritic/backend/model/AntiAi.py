from markdown import Extension
from markdown.inlinepatterns import InlineProcessor
from xml.etree import ElementTree as etree


class AntiAiPattern(InlineProcessor):
    """Inline ``%%text%%`` renders in the decoy font so OCR/vision scrapers
    can't read it while humans still can. The literal characters stay in the
    output — only the rendering font changes (see the .anti-ai CSS)."""

    _ANTI_AI_REGEXP = r"%%(.+?)%%"

    def __init__(self):
        super().__init__(self._ANTI_AI_REGEXP)

    def handleMatch(self, match, data):
        element = etree.Element("span")
        element.text = match.group(1)
        element.attrib["class"] = "anti-ai"
        return element, match.start(0), match.end(0)


class AntiAiExtension(Extension):
    def extendMarkdown(self, md):
        # Priority 201 keeps it just above the spoiler pattern (200) so the two
        # inline markers are handled consistently.
        md.inlinePatterns.register(AntiAiPattern(), "anti-ai", 201)
