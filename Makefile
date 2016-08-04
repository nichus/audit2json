init:
	pip install -r requirements.txt

test:
	nose2 tests

.PHONY: init test
