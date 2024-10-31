

list(APPEND SOURCE
    Disassembler.c
    FuncTableHook.c
    InlineHook.c
    Instruction.c
    Memory.c
    Thread.c
    Trampoline.c
    Transaction.c)

add_library(SlimDetours STATIC ${SOURCE})
target_include_directories(SlimDetours PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_dependencies(SlimDetours psdk)
