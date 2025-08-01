# This file was auto-generated by Polybuild

include_path_flag := -I
library_path_flag := -L
obj_path_flag := -o
out_path_flag := -o
library_flag := -l
static_flag := -static
shared_flag := -shared -fPIC
compile_only_flag := -c
obj_ext := .o
ifeq ($(OS),Windows_NT)
	include_path_flag := /I
	library_path_flag := /LIBPATH:
	obj_path_flag := /Fo:
	out_path_flag := /Fe:
	library_flag :=
	dynamic_flag := /MD
	static_flag := /MT
	shared_flag := /LD
	compile_only_flag := /c
	link_flag := /link
	pkg_config_syntax := --msvc-syntax
	obj_ext := .obj
	out_ext := .exe
endif

c_compiler := $(CC)
cpp_compiler := $(CXX)
c_compilation_flags := $(CFLAGS) $(dynamic_flag) `pkg-config $(pkg_config_syntax) --cflags libadwaita-1 gtk4`
cpp_compilation_flags := -Wall -Wno-unused-result -std=c++17 -O3 $(dynamic_flag) `pkg-config $(pkg_config_syntax) --cflags libadwaita-1 gtk4`
link_time_flags := $(LDFLAGS)
libraries := $(library_flag)ssl $(library_flag)crypto `pkg-config $(pkg_config_syntax) --libs libadwaita-1 gtk4`
prefix := /usr/local/bin

ifeq ($(OS),Windows_NT)
	c_compiler := $(CC)
	cpp_compiler := $(CXX)
	c_compilation_flags := $(CFLAGS) $(static_flag) `pkg-config $(pkg_config_syntax) --cflags libadwaita-1 gtk4`
	cpp_compilation_flags := /W3 /std:c++20 /EHsc /I"$(OPENSSL_ROOT_DIR)"/include /O2 $(static_flag) `pkg-config $(pkg_config_syntax) --cflags libadwaita-1 gtk4`
	link_time_flags := /SUBSYSTEM:WINDOWS $(library_path_flag)"$(OPENSSL_ROOT_DIR)"/lib
	libraries := $(library_flag)libssl.lib $(library_flag)libcrypto.lib $(library_flag)advapi32.lib $(library_flag)crypt32.lib $(library_flag)ws2_32.lib $(library_flag)shcore.lib $(library_flag)shell32.lib `pkg-config $(pkg_config_syntax) --libs libadwaita-1 gtk4`
	prefix := C:\tenebra-gtk\bin
endif

all: tenebra-gtk$(out_ext)
.PHONY: all

obj/util_0$(obj_ext): ./util.cpp ./util.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/main_0$(obj_ext): ./main.cpp ./Polyweb/polyweb.hpp ./Polyweb/Polynet/polynet.hpp ./Polyweb/Polynet/string.hpp ./Polyweb/Polynet/secure_sockets.hpp ./Polyweb/Polynet/smart_sockets.hpp ./Polyweb/string.hpp ./Polyweb/threadpool.hpp ./glib.hpp ./json.hpp ./toml.hpp ./toml/parser.hpp ./toml/combinator.hpp ./toml/region.hpp ./toml/color.hpp ./toml/result.hpp ./toml/traits.hpp ./toml/from.hpp ./toml/into.hpp ./toml/version.hpp ./toml/utility.hpp ./toml/lexer.hpp ./toml/macros.hpp ./toml/types.hpp ./toml/comments.hpp ./toml/datetime.hpp ./toml/string.hpp ./toml/value.hpp ./toml/exception.hpp ./toml/source_location.hpp ./toml/storage.hpp ./toml/literal.hpp ./toml/serializer.hpp ./toml/get.hpp ./util.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/client_0$(obj_ext): Polyweb/client.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/server_0$(obj_ext): Polyweb/server.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/websocket_0$(obj_ext): Polyweb/websocket.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/string_0$(obj_ext): Polyweb/string.cpp Polyweb/string.hpp Polyweb/Polynet/string.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/polyweb_0$(obj_ext): Polyweb/polyweb.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/polynet_0$(obj_ext): Polyweb/Polynet/polynet.cpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

obj/secure_sockets_0$(obj_ext): Polyweb/Polynet/secure_sockets.cpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Compiling $@ from $<..."
	@mkdir -p obj
	@"$(cpp_compiler)" $(compile_only_flag) $< $(cpp_compilation_flags) $(obj_path_flag)$@
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished compiling $@ from $<!"

tenebra-gtk$(out_ext): obj/util_0$(obj_ext) obj/main_0$(obj_ext) obj/client_0$(obj_ext) obj/server_0$(obj_ext) obj/websocket_0$(obj_ext) obj/string_0$(obj_ext) obj/polyweb_0$(obj_ext) obj/polynet_0$(obj_ext) obj/secure_sockets_0$(obj_ext) $(static_libraries)
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Building $@..."
	@"$(cpp_compiler)" $^ $(cpp_compilation_flags) $(out_path_flag)$@ $(link_flag) $(link_time_flags) $(libraries)
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished building $@!"

clean:
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Deleting tenebra-gtk$(out_ext) and obj..."
	@rm -rf tenebra-gtk$(out_ext) obj
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished deleting tenebra-gtk$(out_ext) and obj!"
.PHONY: clean

install:
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Copying tenebra-gtk$(out_ext) to $(prefix)..."
	@cp tenebra-gtk$(out_ext) $(prefix)
	@printf "\033[1m[POLYBUILD]\033[0m %s\n" "Finished copying tenebra-gtk$(out_ext) to $(prefix)!"
.PHONY: install
