# CMakeList.txt: NetRedirector 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.16)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)


# 如果支持，请为 MSVC 编译器启用热重载。
if (POLICY CMP0141)
  message("enable hot-reload")
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project (NetRedirector VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets OpenGL OpenGLWidgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets OpenGL OpenGLWidgets Network)
find_package(spdlog)
find_package(ws2_32)

file(GLOB_RECURSE SOURCES_FILES
    "${CMAKE_SOURCE_DIR}/sources/*.cpp"
    "${CMAKE_SOURCE_DIR}/sources/*.h")
    
message(STATUS "Source files: ${SOURCES_FILES}")

add_executable(NetRedirector
    ${SOURCES_FILES}
)

# 添加引用目录
target_include_directories(NetRedirector PRIVATE ${CMAKE_SOURCE_DIR}/sources)
target_link_libraries(NetRedirector PRIVATE 
    Qt${QT_VERSION_MAJOR}::Widgets Qt${QT_VERSION_MAJOR}::OpenGLWidgets Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network
    spdlog::spdlog "${CMAKE_SOURCE_DIR}/SOURCES/thirdparty/windivert/WinDivert.lib" ws2_32)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message("enable _DEBUG flag")
    target_compile_definitions(NetRedirector PRIVATE -DCXX_DEBUG=1)
endif()

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET NetRedirector PROPERTY CXX_STANDARD 20)
endif()

set_target_properties(NetRedirector PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS NetRedirector
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(NetRedirector)
endif()