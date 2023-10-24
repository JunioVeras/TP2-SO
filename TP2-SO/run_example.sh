#!/bin/bash
set -u

# make
# 1º arg: número do teste

TEST_NUM=$1

while read -r num frames blocks nodiff ; do
    num=$((num))
    frames=$((frames))
    blocks=$((blocks))
    nodiff=$((nodiff))

    if [ $num = $TEST_NUM ]; then
        ./bin/mmu $frames $blocks &> test$TEST_NUM.mmu.out &
        sleep 1s
        ./bin/test$TEST_NUM &> test$TEST_NUM.out
        kill -SIGINT %1
    fi
done < mempager-tests/tests.spec