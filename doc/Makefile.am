info_TEXINFOS           = libfko.texi
SUFFIXES                = .html

html_docs               = libfko.html

.texi.html:
	$(MAKEINFO) --html $<

.PHONY: html
html: version.texi $(html_docs)

