cmake_minimum_required(VERSION 2.8)
project(nfq_filter)

#include(CXX11.cmake)
#check_for_cxx11_compiler(CXX11_COMPILER)
#if(CXX11_COMPILER)
#        enable_cxx11()
#endif()
ADD_DEFINITIONS(
	-std=c++11
)

set(BOOST_COMPONENTS program_options)
find_package(Boost COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
if( NOT Boost_FOUND )
        message(SEND_ERROR "Failed to find boost!")
        return()
else()
        include_directories(${Boost_INCLUDE_DIRS})
endif()

find_library(NFQUEUE_LIB netfilter_queue $ENV{NFQUEUE_LIB_PATH})



set(SOURCE_EXE nfq.cpp)

#set(SOURCE_LIB sender.cpp parser.cpp)
#add_library(sender STATIC ${SOURCE_LIB})

set(NFQ_SOURCES "nfq.cpp" "sender.cpp" "parser.cpp")
add_executable(nfq_filter ${NFQ_SOURCES})

target_link_libraries(nfq_filter -lnetfilter_queue -lpthread -lboost_program_options)
