.phony all:
all: RDPR RDPS

RDPR:
	gcc rdpr.c -o rdpr -lm

RDPS:
	gcc rdps.c -o rdps -lm

clean:
	$(RM) rdpr
	$(RM) rdps
