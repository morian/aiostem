FLAKE8  ?= /usr/bin/flake8
PYTHON  ?= /usr/bin/python3

PHONY += all
all: wheel sdist

PHONY += sdist
sdist:
	$(PYTHON) setup.py sdist

PHONY += wheel
wheel:
	$(PYTHON) setup.py bdist_wheel

PHONY += clean
clean:
	$(RM) --recursive dist build aiostem.egg-info

PHONY += linter
linter:
	$(FLAKE8) --show-source aiostem/

.PHONY: $(PHONY)
