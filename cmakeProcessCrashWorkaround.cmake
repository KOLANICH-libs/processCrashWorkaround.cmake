set(programCrashWorkaroundSourcesDir "${CMAKE_CURRENT_LIST_DIR}/src")

function(programCrashWorkaroundInit targetName)
	add_executable("${targetName}" "${programCrashWorkaroundSourcesDir}/programCrashWorkaround.c")

	set_property(TARGET ${targetName} PROPERTY C_STANDARD 11)
	set_property(TARGET ${targetName} PROPERTY CXX_STANDARD 20)

	if(WIN32)
		target_link_libraries(${targetName} -lshlwapi)
		if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
			target_compile_options(${targetName} PRIVATE "-municode")
		endif()
	endif()
endfunction()
