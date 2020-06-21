# If you make changes to this file and want to implement them, make sure you cd into build dir and delete all older files, like so:
# rm -rf ./*
# cmake ..
# make




cmake_minimum_required (VERSION 3.10.2)



# Set the project name.
project("CRL-OCSP-Validator")




# Tell the compiler which directories have the user-generated non-standard header files. We just have one, that is, (./include).
include_directories( ./include  )



# Paths of all source files will get stored in this variable.
set(SOURCE_FILES
	./src/application.cpp
	./src/Common.cpp
	./src/ChainFileFunctions.cpp
	./src/CRLFunctions.cpp
	./src/OCSPFunctions.cpp
) 




# Add the target.
add_executable(
	application # this will be the name of the executable.
	${SOURCE_FILES}
)




# Find the openssl package.
find_package(OpenSSL REQUIRED)




# target_link_libraries(application OpenSSL::Crypto)
target_link_libraries(application OpenSSL::SSL)

# Looks like SSL is a superset of Crypto, so the first target_link_libraries call is not needed.
