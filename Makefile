DEBUILD   ?= /usr/bin/debuild
FLAKE8    ?= /usr/bin/flake8
PYTHON    ?= /usr/bin/python3

PHONY += all
all: wheel sdist

PHONY += bdist sdist
bdist sdist:
	$(PYTHON) setup.py $@

PHONY += wheel
wheel:
	$(PYTHON) setup.py bdist_wheel

PHONY += clean
clean:
	$(RM) --recursive dist build aiostem.egg-info

PHONY += linter
linter:
	$(FLAKE8) --show-source aiostem/ bin/aiostem-hsscan

PHONY += deb
deb: debian/changelog
	$(DEBUILD) -i -us -uc -b

.PHONY: $(PHONY)
