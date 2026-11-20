add_executable(VerifyMilestone2
    VerifyMilestone2.cpp
    ../src/process/ProcessInspector.cpp
    ../src/process/ProcessKiller.cpp
)

target_include_directories(VerifyMilestone2 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(VerifyMilestone2 PRIVATE
        /W4 /WX /permissive- /utf-8 /Zc:__cplusplus
    )
    target_compile_definitions(VerifyMilestone2 PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
    )
endif()

add_executable(VerifyMilestone3
    VerifyMilestone3.cpp
    ../src/monitors/PayloadClassifier.cpp
)

target_include_directories(VerifyMilestone3 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(VerifyMilestone3 PRIVATE
        /W4 /WX /permissive- /utf-8 /Zc:__cplusplus
    )
    target_compile_definitions(VerifyMilestone3 PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
    )
endif()

add_executable(VerifyMilestone4
    VerifyMilestone4.cpp
    ../src/core/Allowlist.cpp
    ../src/core/EventBus.cpp
    ../src/monitors/DeviceMonitor.cpp
)

target_include_directories(VerifyMilestone4 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(VerifyMilestone4 PRIVATE
        /W4 /WX /permissive- /utf-8 /Zc:__cplusplus
    )
    target_compile_definitions(VerifyMilestone4 PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
    )
endif()

add_executable(VerifyMilestone5
    VerifyMilestone5.cpp
    ../src/core/EventBus.cpp
    ../src/monitors/NetworkMonitor.cpp
    ../src/process/ProcessInspector.cpp
)

target_include_directories(VerifyMilestone5 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(VerifyMilestone5 PRIVATE
    iphlpapi
    ws2_32
)

if(MSVC)
    target_compile_options(VerifyMilestone5 PRIVATE
        /W4 /WX /permissive- /utf-8 /Zc:__cplusplus
    )
    target_compile_definitions(VerifyMilestone5 PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
    )
endif()
