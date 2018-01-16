CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT (vserv_ns)

LIST(APPEND CMAKE_MODULE_PATH
	${CMAKE_SOURCE_DIR}/cmake/Modules
)

SET(VSERV_NS_HEADERS
	include/vserv/ns_vserv_helpers.h
)
SET(VSERV_NS_SOURCES
	src/ns_vserv_net_main.cpp
)

FIND_PACKAGE(ENet REQUIRED)

## http://stackoverflow.com/questions/1620918/cmake-and-libpthread/29871891#29871891
## https://cmake.org/cmake/help/v3.6/module/FindThreads.html
##   extra magic for gcc linking with pthreads (-pthread)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)

SET(GITTEST_DEP_INCLUDE_DIRS
  ${ENET_INCLUDE_DIR}
)
SET (GITTEST_DEP_LIBRARIES
  ${ENET_LIBRARIES}
  Threads::Threads
)

ADD_EXECUTABLE(vserv_ns ${VSERV_NS_HEADERS} ${VSERV_NS_SOURCES})
SET_PROPERTY(TARGET vserv_ns PROPERTY SUFFIX ".exe")
TARGET_LINK_LIBRARIES(vserv_ns Threads::Threads ${ENET_LIBRARIES})
TARGET_INCLUDE_DIRECTORIES(vserv_ns PUBLIC ${CMAKE_SOURCE_DIR}/include ${ENET_INCLUDE_DIR})
