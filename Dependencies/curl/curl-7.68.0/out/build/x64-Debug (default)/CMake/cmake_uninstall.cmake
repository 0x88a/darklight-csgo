if(NOT EXISTS "C:/Users/jeff/Files/Cheating/darklight-master/Dependencies/curl/curl-7.68.0/out/build/x64-Debug (default)/install_manifest.txt")
  message(FATAL_ERROR "Cannot find install manifest: C:/Users/jeff/Files/Cheating/darklight-master/Dependencies/curl/curl-7.68.0/out/build/x64-Debug (default)/install_manifest.txt")
endif()

if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Users/jeff/Files/Cheating/darklight-master/Dependencies/curl/curl-7.68.0/out/install/x64-Debug (default)")
endif()
message(${CMAKE_INSTALL_PREFIX})

file(READ "C:/Users/jeff/Files/Cheating/darklight-master/Dependencies/curl/curl-7.68.0/out/build/x64-Debug (default)/install_manifest.txt" files)
string(REGEX REPLACE "\n" ";" files "${files}")
foreach(file ${files})
  message(STATUS "Uninstalling $ENV{DESTDIR}${file}")
  if(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
    exec_program(
      "C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" ARGS "-E remove \"$ENV{DESTDIR}${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    if(NOT "${rm_retval}" STREQUAL 0)
      message(FATAL_ERROR "Problem when removing $ENV{DESTDIR}${file}")
    endif()
  else()
    message(STATUS "File $ENV{DESTDIR}${file} does not exist.")
  endif()
endforeach()
