PIP_INDEX_URL = https://pypi.python.org/simple
IMAGE ?= ghcr.io/finitelabs/zigbee-firmware-index

ifeq ($(VIRTUAL_ENV),)
$(error must run in a virtualenv)
else
$(info running in virtualenv $(VIRTUAL_ENV))
endif

.PHONY: all
all: init install check test

.PHONY: init
init:
	pip install -i $(PIP_INDEX_URL) -U setuptools pip wheel pip-tools

.PHONY: install
install: requirements.txt requirements-dev.txt
	pip-sync -i $(PIP_INDEX_URL) requirements.txt requirements-dev.txt

upgrade = $(or $(UPGRADE),0)
ifneq ($(upgrade),0)
pip_compile_flags += --upgrade --rebuild
endif
pip_compile = pip-compile -i $(PIP_INDEX_URL) --no-strip-extras $(pip_compile_flags)

requirements.txt: requirements.in
	$(pip_compile) $< -o $@

requirements-dev.txt: requirements-dev.in requirements.txt
	$(pip_compile) $< -o $@

.PHONY: fmt
fmt:
	black .

.PHONY: check
check:
	black --check .

.PHONY: test
test:
	pytest

.PHONY: dev
dev:
	PYTHONPATH=src python -m firmware_index serve --local .dev

.PHONY: image
image:
	docker build -t $(IMAGE):dev .
