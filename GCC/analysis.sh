#!/bin/bash

set -euo pipefail

# Options
OPT_COMPILER_TYPE=""
OPT_COMPILER_OPTIONS=""
OPT_RUN_CMD=""

function args {
    OPTIND=1
    options=$(getopt -o h --long clang,gcc,ast,asm,cfg,pre,ir,delete -- "$@")
    [ $? -eq 0 ] || {
        echo "Incorrect options provided"
        exit 1
    }

    eval set -- "$options"
    while [ $# -ge 1 ] ; do
        case "$1" in
            -h)
                echo "Build printing-service"
                echo "  -h              : print this list of options"
                echo "  --clang         : build using clang compiler"
                echo "  --gcc           : build using gcc compiler"
                echo "  --ast           : build displaying abstract syntax tree"
                echo "  --asm           : build displaying assembly"
                echo "  --pre           : build displaying preprocessor output"
                echo "  --cfg           : build generating something something graph"
                exit 0
                ;;
            -c | --clang)
                OPT_COMPILER_TYPE=clang++
                OPT_COMPILER_OPTIONS="-std=c++17 -stdlib=libc++"
                ;;
            -g | --gcc)
                OPT_COMPILER_TYPE=g++
                OPT_COMPILER_OPTIONS="-std=c++17"
                ;;
            --ast)
                OPT_RUN_CMD=AST
                ;;
            --asm)
                OPT_RUN_CMD=ASM
                ;;
            --pre)
                OPT_RUN_CMD=PRE
                ;;
            --cfg)
                OPT_RUN_CMD=CFG
                ;;
            --ir)
                OPT_RUN_CMD=IR
                ;;
            --delete)
                OPT_RUN_CMD=DELETE
                ;;
        esac
        shift
    done
}

function ast {
    case $OPT_COMPILER_TYPE in
        g++)
            ${OPT_COMPILER_TYPE} main.cpp -fdump-tree-original ${OPT_COMPILER_OPTIONS} -o example
            ;;
        clang++)
            # https://clang.llvm.org/docs/IntroductionToTheClangAST.html
            # -Xclang is a way to pass arguments to the C++ frontend of clang
            ${OPT_COMPILER_TYPE} -Xclang -ast-dump -fsyntax-only main.cpp ${OPT_COMPILER_OPTIONS} -o example
            ;;
    esac
}

function asm {
    ${OPT_COMPILER_TYPE} -S -O3 main.cpp ${OPT_COMPILER_OPTIONS}
}

function preprocessor {
    # Output the preprocessor stage for a C++ source
    ${OPT_COMPILER_TYPE} -E -O3 main.cpp ${OPT_COMPILER_OPTIONS} > main.cpp.E
    # Output the preprocessor stage for a C++ source with macros and defines
    ${OPT_COMPILER_TYPE} -E -O3 main_macro.cpp ${OPT_COMPILER_OPTIONS} > main_macro.cpp.E

    case $OPT_COMPILER_TYPE in
        g++)
            # Output the preprocessor stage for a C source
            gcc -E -O3 main.c > main.c.E
            ;;
        clang++)
            # Output the preprocessor stage for a C source
            clang -E -O3 main.c > main.c.E
            ;;
    esac
}

function cfg {
    # Output Control Flow Graph (CFG)
    case $OPT_COMPILER_TYPE in
        g++)
            ${OPT_COMPILER_TYPE} main.cpp -fdump-tree-cfg -o example3
            ;;
        clang++)
            ${OPT_COMPILER_TYPE} -emit-llvm main.cpp -c -o main.bc 
            opt -dot-cfg-only main.bc
            dot -Tpng cfg.main.dot -o CFG.png
            ;;
    esac
}

function ir {
    # Output IR output
    case $OPT_COMPILER_TYPE in
        g++)
            ${OPT_COMPILER_TYPE} main.cpp ${OPT_COMPILER_OPTIONS} -da -o example4
            ;;
        clang++)
            ${OPT_COMPILER_TYPE} -S -emit-llvm main.cpp ${OPT_COMPILER_OPTIONS} -o example4
            ;;
    esac
}

function delete {
    rm main.cpp.* || true
    rm *.png || true
    rm example* || true
    rm main.s || true
    rm main.c.E || true
    rm main_macro.cpp.E || true
    rm main.bc || true
    rm *.dot || true
}

args $0 "$@"

case $OPT_RUN_CMD in
    AST)
        ast
        ;;
    ASM)
        asm
        ;;
    PRE)
        preprocessor
        ;;
    CFG)
        cfg
        ;;
    IR)
        ir
        ;;
    DELETE)
        delete
        ;;
    *)
        echo "I FAILED"
        ;;
esac
