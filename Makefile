.DEFAULT_GOAL := all
sources = aiostem tests bin/aiostem-hsscan
DEBUILD ?= /usr/bin/debuild

.PHONY: install-linting
install-linting:
	pip install -r tests/requirements-linter.txt

.PHONY: install-aiostem
install-aiostem:
	pip install -U build pip wheel
	pip install -e .

.PHONY: install-testing
install-testing: install-aiostem
	pip install -r tests/requirements-testing.txt

.PHONY: install
install: install-testing install-linting
	@echo 'Installed development requirements'

.PHONY: build
build:
	python -m build --wheel --sdist

.PHONY: deb
deb: debian/changelog
	$(DEBUILD) -i -us -uc -b

.PHONY: format
format:
	isort $(sources)
	black $(sources)

.PHONY: lint
lint:
	ruff check $(sources)
	isort $(sources) --check-only --df
	black $(sources) --check --diff

.PHONY: mypy
mypy:
	mypy aiostem bin/aiostem-hsscan

.PHONY: all
all: lint mypy

.PHONY: test
test:
	pytest --cov=aiostem

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
	$(RM) -r .ruff_cache
	$(RM) -r build
	$(RM) -r dist
	$(RM) -r htmlcov
	find aiostem -name '*.py[cod]' -delete
