.PHONY: dist test doctest publish

test:
	python3 -m unittest discover -v test.unit.redstone

doctest:
	python3 -m doctest -o ELLIPSIS README.md

dist:
	python setup.py sdist bdist_wheel

publish: dist
	pip install 'twine>=1.5.0'
	twine upload --repository redstone --skip-existing dist/*
	rm -fr build dist .egg *.egg-info

fmt: black

lint: mypy

black:
	black -t py35 redstone test

mypy:
	mypy redstone
