# Host tests for the component's platform-free parts: `make -C tests`.

CXX ?= g++
CXXFLAGS ?= -std=gnu++20 -O1 -g -Wall -Wextra -Werror -Wno-unused-parameter
CPPFLAGS += -DNIBEGW_TGW_HOST_TEST
PYTHON ?= python3

COMPONENT := ../components/nibegw
SOURCES := main.cpp sha256.cpp $(wildcard test_*.cpp) \
	$(COMPONENT)/TgwProtocol.cpp $(COMPONENT)/TgwCrypto.cpp \
	$(wildcard $(COMPONENT)/TgwEngine.cpp) $(wildcard $(COMPONENT)/TgwControl.cpp)

.PHONY: test clean
test: build/tests
	./build/tests

build/vectors.inc: vectors/thermaestro-gw.json gen_vectors.py
	@mkdir -p build
	$(PYTHON) gen_vectors.py $< $@

build/tests: $(SOURCES) $(wildcard *.h) $(wildcard $(COMPONENT)/Tgw*.h) $(COMPONENT)/NibeGwRequest.h build/vectors.inc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(SOURCES)

clean:
	rm -rf build
