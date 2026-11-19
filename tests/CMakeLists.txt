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
