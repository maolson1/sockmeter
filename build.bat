@echo off

if exist build rmdir /s /q build
mkdir build
cd build
cmake -A x64 ..
cmake --build . --config Debug --target sockmeter && ^
cmake --build . --config Release --target sockmeter && ^
cmake --build . --config Release --target stats_test
cd..
