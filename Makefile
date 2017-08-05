RM = rm -f
FIND = find .

all:

clean:
	$(RM) -r build dist *.egg-info
	$(FIND) -name '*~' -delete
	$(FIND) -name '*.pyc' -delete
	$(FIND) -name '__pycache__' -delete

.PHONY: all clean
