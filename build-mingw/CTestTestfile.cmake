# CMake generated Testfile for 
# Source directory: C:/FinalLab/MSV.All6labs/lab2
# Build directory: C:/FinalLab/MSV.All6labs/lab2/build-mingw
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
include("C:/FinalLab/MSV.All6labs/lab2/build-mingw/aes_tests[1]_include.cmake")
add_test(cli_kat "C:/FinalLab/MSV.All6labs/lab2/build-mingw/aestool.exe" "--kat" "C:/FinalLab/MSV.All6labs/lab2/nist_vectors.json")
set_tests_properties(cli_kat PROPERTIES  _BACKTRACE_TRIPLES "C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;84;add_test;C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;0;")
add_test(cli_negative "C:/FinalLab/MSV.All6labs/lab2/build-mingw/aestool.exe" "--test-negative")
set_tests_properties(cli_negative PROPERTIES  _BACKTRACE_TRIPLES "C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;89;add_test;C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;0;")
add_test(cli_rng_keygen_geniv "C:/Program Files/CMake/bin/cmake.exe" "-DAESTOOL=C:/FinalLab/MSV.All6labs/lab2/build-mingw/aestool.exe" "-DWORKDIR=C:/FinalLab/MSV.All6labs/lab2/build-mingw/rng_test" "-P" "C:/FinalLab/MSV.All6labs/lab2/scripts/test_rng_keygen.cmake")
set_tests_properties(cli_rng_keygen_geniv PROPERTIES  _BACKTRACE_TRIPLES "C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;94;add_test;C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;0;")
add_test(cli_counter_overflow "C:/Program Files/CMake/bin/cmake.exe" "-DAESTOOL=C:/FinalLab/MSV.All6labs/lab2/build-mingw/aestool.exe" "-DWORKDIR=C:/FinalLab/MSV.All6labs/lab2/build-mingw/counter_overflow_test" "-P" "C:/FinalLab/MSV.All6labs/lab2/scripts/test_counter_overflow.cmake")
set_tests_properties(cli_counter_overflow PROPERTIES  _BACKTRACE_TRIPLES "C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;104;add_test;C:/FinalLab/MSV.All6labs/lab2/CMakeLists.txt;0;")
subdirs("_deps/googletest-build")
