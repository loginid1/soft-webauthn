.PHONY: all venv install-deps lint test coverage

all: lint coverage

venv:
	sudo apt-get -y install python-virtualenv python3-virtualenv
	virtualenv -p python3 venv

install-deps:
	pip install -r requirements.txt

freeze:
	@pip freeze | grep -v '^pkg-resources='

lint:
	python -m flake8 soft_webauthn.py tests/
	python -m pylint soft_webauthn.py tests/

test:
	python -m pytest -v

coverage:
	coverage run --source soft_webauthn -m pytest tests -x -vv
	coverage report --show-missing --fail-under 100
