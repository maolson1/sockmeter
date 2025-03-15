@echo off

if exist build rmdir /s /q build
mkdir build
cd build
cmake -A x64 ..
cmake --build . --config Release
cd..
