CC = gcc
FLAGS = -Wall -Wextra
SOURCES = main.c pss_config.c pss_log.c portscanshield.c ip_knock_info.c signal_handlers.c pss_pidfile.c handle_argv.c cidr_bitmask.c vector_template/vector_template.c
LIBS = -lconfuse
TEST_SOURCES = tests/parse_config_test.c
TEST_LIBS = -lcheck -lpthread -lm -lrt
APPNAME = portscanshield

all:
	$(CC) $(FLAGS) -O3 $(SOURCES) $(LIBS) -o $(APPNAME)

debug:
	$(CC) $(FLAGS) -g $(SOURCES) $(LIBS) -o debug_$(APPNAME)
