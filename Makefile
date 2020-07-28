.PHONY: dist test publish

test:
	python3 -m doctest -o ELLIPSIS README.md

dist:
	python setup.py sdist bdist_wheel

publish:
	pip install 'twine>=1.5.0'
	twine upload dist/*
	rm -fr build dist .egg *.egg-info
