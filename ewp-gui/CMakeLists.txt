cmake_minimum_required(VERSION 3.16)
project(EWP-GUI VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt6 配置
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

# 源文件
set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/CoreProcess.cpp
    src/NodeManager.cpp
    src/SystemProxy.cpp
    src/NodeTester.cpp
    src/ShareLink.cpp
    src/EditNodeDialog.cpp
)

set(HEADERS
    src/MainWindow.h
    src/CoreProcess.h
    src/NodeManager.h
    src/SystemProxy.h
    src/NodeTester.h
    src/ShareLink.h
    src/EWPNode.h
    src/EditNodeDialog.h
)

set(UI_FILES
    ui/MainWindow.ui
    ui/EditNodeDialog.ui
    ui/Settings.ui
)

set(RESOURCES
    resources/resources.qrc
)

# 可执行文件
add_executable(${PROJECT_NAME} WIN32
    ${SOURCES}
    ${HEADERS}
    ${UI_FILES}
    ${RESOURCES}
)

# 包含目录
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${CMAKE_CURRENT_BINARY_DIR}
)

# 设置 AUTOUIC 路径
set_target_properties(${PROJECT_NAME} PROPERTIES
    AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui
)

# 链接 Qt 库
target_link_libraries(${PROJECT_NAME}
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

# Windows 特定配置
if(WIN32)
    target_link_libraries(${PROJECT_NAME} wininet)
endif()

# 安装规则
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
