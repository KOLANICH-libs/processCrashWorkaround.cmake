cmake_minimum_required(VERSION 3.19)
project(processCrashWorkaround)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_LIST_DIR}")
include(cmakeProcessCrashWorkaround)
programCrashWorkaroundInit(processCrashWorkaround)
