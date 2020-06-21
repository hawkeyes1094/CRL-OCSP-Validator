# CRL-OCSP-Validator
6th semester project offered by HP Enterprises on certificate chain validation using CRLs and OCSP.

Instructions to install (for Ubuntu based systems):

After cloning the directory,
0. Install the OpenSSL library => [sudo apt-get install libssl-dev]
1. Make a build directory => [mkdir build]
2. Go into into build directory => [cd build]
3. Run cmake (CMakeLists.txt is in the root) => [cmake ..]
4. run make => [make]

The executable (called application) will be created in the build directory. Can be run with [./application]
