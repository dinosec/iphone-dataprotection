link_directories(${PROJECT_BINARY_DIR}/common ${PROJECT_BINARY_DIR}/hfs)

#set(COREFOUNDATION_LIBRARY CoreFoundation)

IF (APPLE)
   FIND_LIBRARY(COREFOUNDATION_LIBRARY CoreFoundation)
ENDIF (APPLE)

add_executable(emf_decrypter emf_decrypter.c emf_init.c)
target_link_libraries (emf_decrypter hfs common crypto ${COREFOUNDATION_LIBRARY})

install(TARGETS emf_decrypter DESTINATION .)
