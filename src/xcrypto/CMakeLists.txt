set(xcrypto_sources
    convert_test.cpp
    xcrypto.cpp)

set(xcrypto_headers
    convert.hpp
    tlvserializer.hpp
    xcrypto.h)

monero_private_headers(xxcrypto
  ${xcrypto_headers})
monero_add_library(xxcrypto
  ${xcrypto_sources})

target_link_libraries(xxcrypto
    PUBLIC
      epee
      common
      cncrypto
      checkpoints
      cryptonote_basic
      ringct_basic
      ringct
      device
      mnemonics
      version
      ${UNBOUND_LIBRARY}
      ${LIBUNWIND_LIBRARIES}
      ${Boost_SYSTEM_LIBRARY}
      ${Boost_DATE_TIME_LIBRARY}
      ${Boost_PROGRAM_OPTIONS_LIBRARY}
      ${Boost_SERIALIZATION_LIBRARY}
      ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_SYSTEM_LIBRARY}
      ${Boost_THREAD_LIBRARY}
      ${Boost_REGEX_LIBRARY}
      ${Boost_CHRONO_LIBRARY}
      ${SODIUM_LIBRARY}
      ${OPENSSL_CRYPTO_LIBRARIES}

    PRIVATE
      ${OPENSSL_LIBRARIES}
      ${EXTRA_LIBRARIES})

install (FILES ${xcrypto_headers} DESTINATION include/xcrypto)

set(libxcrypto_to_merge
      version
      easylogging 
      epee
      unbound
      common
      cncrypto
      checkpoints
      cryptonote_basic
      ringct_basic
      ringct
      device
      mnemonics
      version
      xxcrypto)

foreach(lib ${libxcrypto_to_merge})
    list(APPEND objlibs $<TARGET_OBJECTS:obj_${lib}>)
endforeach()
add_library(xcrypto STATIC ${objlibs})
install(TARGETS xcrypto ARCHIVE DESTINATION lib)


# add_executable(xcrypto-test xcrypto_test.c)
# target_link_libraries(xcrypto-test
#     PUBLIC
#       xcrypto
#       version
#       ${HIDAPI_LIBRARIES}
#       ${UNBOUND_LIBRARY}
#       ${LIBUNWIND_LIBRARIES}
#       ${Boost_SYSTEM_LIBRARY}
#       ${Boost_DATE_TIME_LIBRARY}
#       ${Boost_PROGRAM_OPTIONS_LIBRARY}
#       ${Boost_SERIALIZATION_LIBRARY}
#       ${Boost_FILESYSTEM_LIBRARY}
#       ${Boost_SYSTEM_LIBRARY}
#       ${Boost_THREAD_LIBRARY}
#       ${Boost_REGEX_LIBRARY}
#       ${Boost_CHRONO_LIBRARY}
#       ${SODIUM_LIBRARY}
#       ${OPENSSL_CRYPTO_LIBRARIES}

#     PRIVATE
#       ${OPENSSL_LIBRARIES}
#       ${EXTRA_LIBRARIES})

# install (TARGETS xcrypto-test DESTINATION bin)

add_executable(xtlv-test tlv_test.cpp tlvserializer.hpp)
target_link_libraries(xtlv-test
        PUBLIC
        xcrypto
        version
        ${HIDAPI_LIBRARIES}
        ${UNBOUND_LIBRARY}
        ${LIBUNWIND_LIBRARIES}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_DATE_TIME_LIBRARY}
        ${Boost_PROGRAM_OPTIONS_LIBRARY}
        ${Boost_SERIALIZATION_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_THREAD_LIBRARY}
        ${Boost_REGEX_LIBRARY}
        ${Boost_CHRONO_LIBRARY}
        ${SODIUM_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARIES}

        PRIVATE
        ${OPENSSL_LIBRARIES}
        ${EXTRA_LIBRARIES})

install (TARGETS xtlv-test DESTINATION bin)

# add_executable(bench-test rctsig_bench_test.cpp)
# target_link_libraries(bench-test
#     PUBLIC
#       xcrypto
#       version
#       ${HIDAPI_LIBRARIES}
#       ${UNBOUND_LIBRARY}
#       ${LIBUNWIND_LIBRARIES}
#       ${Boost_SYSTEM_LIBRARY}
#       ${Boost_DATE_TIME_LIBRARY}
#       ${Boost_PROGRAM_OPTIONS_LIBRARY}
#       ${Boost_SERIALIZATION_LIBRARY}
#       ${Boost_FILESYSTEM_LIBRARY}
#       ${Boost_SYSTEM_LIBRARY}
#       ${Boost_THREAD_LIBRARY}
#       ${Boost_REGEX_LIBRARY}
#       ${Boost_CHRONO_LIBRARY}
#       ${SODIUM_LIBRARY}
#       ${OPENSSL_CRYPTO_LIBRARIES}

#     PRIVATE
#       ${OPENSSL_LIBRARIES}
#       ${EXTRA_LIBRARIES})

# install (TARGETS bench-test DESTINATION bin)
