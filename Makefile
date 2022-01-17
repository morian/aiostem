.DEFAULT_GOAL := all

DEBUILD   ?= /usr/bin/debuild

LINTER_SOURCES =      \
	aiostem/            \
	bin/aiostem-hsscan  \
	setup.py
isort = isort $(LINTER_SOURCES)
black = black -S -l 95 $(LINTER_SOURCES)
pydocstyle = pydocstyle --explain --source $(LINTER_SOURCES)

.PHONY: install-linter
install-linter:
	pip install -r tests/requirements-linter.txt

.PHONY: install-aiostem
install-aiostem:
	pip install -U build pip wheel
	pip install -e .

.PHONY: install
install: install-aiostem install-linter
	@echo 'Installed development requirements'

.PHONY: build
build:
	python -m build --wheel --sdist

.PHONY: deb
deb: debian/changelog
	$(DEBUILD) -i -us -uc -b

.PHONY: format
format:
	$(isort)
	$(black)

.PHONY: lint
lint:
	flake8 $(LINTER_SOURCES)
	$(isort) --check-only --df
	$(black) --check --diff --color
	$(pydocstyle)

.PHONY: mypy
mypy:
	mypy $(LINTER_SOURCES)

.PHONY: all
all: lint mypy

.PHONY: clean
clean:
	rm -rf *.egg-info
	rm -rf .mypy_cache
	rm -rf .pytest_cache
	rm -rf build
	rm -rf dist
	find aiostem -name '*.py[cod]' -delete
