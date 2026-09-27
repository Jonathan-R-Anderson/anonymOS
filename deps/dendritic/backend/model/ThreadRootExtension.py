from model.ThreadPostProcessor import ThreadPostprocessor
# TODO: Enable \r\n to <br /> support for imported posts.
from markdown import Extension


class ThreadRootExtension(Extension):
    def extendMarkdown(self, md):
        md.postprocessors.register(ThreadPostprocessor(), "threadroot", 0)
