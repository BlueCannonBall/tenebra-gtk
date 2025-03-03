# This file was auto-generated by Polybuild

ifndef OS
	OS := $(shell uname)
endif

obj_ext := .o
ifeq ($(OS),Windows_NT)
	obj_ext := .obj
	out_ext := .exe
endif

compiler := $(CXX)
compilation_flags := -Wall -Wno-unused-result -std=c++17 -O3 `pkg-config --cflags libadwaita-1 gtk4`
libraries := `pkg-config --libs libadwaita-1 gtk4`

default: tenebra-gtk$(out_ext)
.PHONY: default

obj/main_0$(obj_ext): ./main.cpp ./glib.hpp ./toml.hpp ./toml/parser.hpp ./toml/combinator.hpp ./toml/region.hpp ./toml/color.hpp ./toml/result.hpp ./toml/traits.hpp ./toml/from.hpp ./toml/into.hpp ./toml/version.hpp ./toml/utility.hpp ./toml/lexer.hpp ./toml/macros.hpp ./toml/types.hpp ./toml/comments.hpp ./toml/datetime.hpp ./toml/string.hpp ./toml/value.hpp ./toml/exception.hpp ./toml/source_location.hpp ./toml/storage.hpp ./toml/literal.hpp ./toml/serializer.hpp ./toml/get.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

tenebra-gtk$(out_ext): obj/main_0$(obj_ext)
	@printf '\033[1m[POLYBUILD]\033[0m Building $@...\n'
	@$(compiler) $^ $(static_libraries) $(compilation_flags) $(libraries) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished building $@!\n'

clean:
	@printf '\033[1m[POLYBUILD]\033[0m Deleting tenebra-gtk$(out_ext) and obj...\n'
	@rm -rf tenebra-gtk$(out_ext) obj
	@printf '\033[1m[POLYBUILD]\033[0m Finished deleting tenebra-gtk$(out_ext) and obj!\n'
.PHONY: clean

install:
	@printf '\033[1m[POLYBUILD]\033[0m Copying tenebra-gtk$(out_ext) to /usr/local/bin...\n'
	@cp tenebra-gtk$(out_ext) /usr/local/bin
	@printf '\033[1m[POLYBUILD]\033[0m Finished copying tenebra-gtk to /usr/local/bin!\n'
.PHONY: install
