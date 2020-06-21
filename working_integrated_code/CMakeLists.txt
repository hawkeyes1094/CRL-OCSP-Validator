# rm -rf ./*
# cmake ..
# make


cmake_minimum_required (VERSION 3.10.2)

# set the project name
project("CRL-OCSP-Validator")

# find openssl package
find_package(OpenSSL REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)

#flags




#files




#include files (folders where compiler should look for header files)
include_directories( ./include  )


set(SOURCE_FILES # paths of all source files will get stored in this variable/
	./src/application.cpp
	./src/Common.cpp
	./src/ChainFileFunctions.cpp
	./src/CRLFunctions.cpp
	./src/OCSPFunctions.cpp
) 

#target
add_executable(
	application # this will be the name of the executable.
	${SOURCE_FILES}
)

target_link_libraries(application OpenSSL::Crypto)
target_link_libraries(application OpenSSL::SSL)
target_link_libraries(application ${CMAKE_DL_LIBS})


