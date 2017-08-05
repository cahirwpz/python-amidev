RM = rm -f

all:

clean:
	$(RM) -r build dist *~

.PHONY: all clean
