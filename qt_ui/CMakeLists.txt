cmake_minimum_required(VERSION 3.16)
project(limits_ui_qt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Widgets QUIET)
find_package(Qt5 COMPONENTS Widgets QUIET)

if (Qt6_FOUND)
    set(QT_LIBS Qt6::Widgets)
elseif (Qt5_FOUND)
    set(QT_LIBS Qt5::Widgets)
else()
    message(FATAL_ERROR
        "Qt Widgets development package not found. Install Qt6 or Qt5 dev files "
        "(Qt6Config.cmake / Qt5Config.cmake), or set CMAKE_PREFIX_PATH / Qt*_DIR.")
endif()

add_executable(limits_ui_qt
    main.cpp
)

target_link_libraries(limits_ui_qt PRIVATE ${QT_LIBS})
