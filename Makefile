
test:
	python3 -m doctest -o ELLIPSIS README.md

publish:
	pip install 'twine>=1.5.0'
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist .egg redstone.egg-info
