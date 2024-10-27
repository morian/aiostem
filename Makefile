.DEFAULT_GOAL := all

DEBUILD ?= /usr/bin/debuild

.PHONY: install-devel
install-devel:
	pip install -r tests/requirements-devel.txt

.PHONY:
install-docs: install-package
	pip install -r docs/requirements.txt

.PHONY: install-linting
install-linting:
	pip install -r tests/requirements-linting.txt

.PHONY: install-package
install-package:
	pip install -U build pip wheel
	pip install -e .

.PHONY: install-testing
install-testing: install-package
	pip install -r tests/requirements-testing.txt

.PHONY: install
install: install-devel install-docs install-testing install-linting
	@echo 'Installed development requirements'

.PHONY: build
build:
	python -m build --wheel --sdist

.PHONY: htmldoc
htmldoc:
	$(MAKE) -C docs/ html

.PHONY: deb
deb: debian/changelog
	$(DEBUILD) -i -us -uc -b

.PHONY: format
format:
	ruff check --select=I --fix-only
	ruff format

.PHONY: lint
lint:
	ruff check
	ruff format --check --diff

.PHONY: mypy
mypy:
	mypy

.PHONY: all
all: lint mypy testcov

.PHONY: test
test:
	pytest

.PHONY: testcov
testcov: test
	@echo "building coverage html"
	@coverage html

.PHONY: clean
clean:
	$(RM) .coverage
	$(RM) .coverage.*
	$(RM) -r *.egg-info
	$(RM) -r .mypy_cache
	$(RM) -r .pytest_cache
	$(RM) -r build
	$(RM) -r dist
	$(RM) -r htmlcov
	find aiostem tests -name '*.py[cod]' -delete
	ruff clean
