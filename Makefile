.PHONY: dist

dist:
	python setup.py sdist bdist_wheel

publish: dist
	pip install 'twine>=1.5.0'
	twine upload dist/*
	rm -fr build dist .egg *.egg-info

setup: deps dev_deps

deps:
	python -m pip install -r requirements.txt

dev_deps:
	python -m pip install -r requirements-dev.txt

ci: setup lint

lint:
	./pylint.sh

# This needs a valid IBMCLOUD_API_KEY in cloud.ibm.com to run the test
test:
	python -m unittest test.unit.redstone.test_auth
	python -m unittest test.integration.test_resourcecontroller
	python -m unittest test.integration.test_keyprotect