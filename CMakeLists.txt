cmake_minimum_required(VERSION 2.8)
project(nfq_filter)

# c++11
include(CXX11.cmake)
check_for_cxx11_compiler(CXX11_COMPILER)
if(CXX11_COMPILER)
        enable_cxx11()
else()
	message( FATAL_ERROR "c++11 compatible compiler not found!" )
endif()

# check libnetfilter (test)
#find_library(
# end check libnetfilter (test)

# check libnetfilter headers
INCLUDE(CheckIncludeFiles)
CHECK_INCLUDE_FILES("libnetfilter_queue/libnetfilter_queue.h" HAVE_NFQUEUE_H)
if(NOT HAVE_NFQUEUE_H)
	message( FATAL_ERROR "libnetfilter_queue.h not found!" )
endif()

find_library(NFQUEUE_LIB netfilter_queue $ENV{NFQUEUE_LIB_PATH})

set(SOURCE_EXE nfq.cpp)

set(NFQ_SOURCES "nfq.cpp" "config.cpp" "sender.cpp" "parser.cpp")
add_executable(nfq_filter ${NFQ_SOURCES})

target_link_libraries(nfq_filter -lnetfilter_queue -lpthread -lnfnetlink)
