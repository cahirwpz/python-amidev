RM = rm -f
FIND = find .
PYTHON = python3

all:

install:
	$(PYTHON) setup.py install --user --prefix=

clean:
	$(RM) -r build dist *.egg-info
	$(FIND) -name '*~' -delete
	$(FIND) -name '*.pyc' -delete
	$(FIND) -name '__pycache__' -delete

.PHONY: all install clean
