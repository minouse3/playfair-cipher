@echo off
REM ===========================================================================
REM  Build the standalone Playfair Breaker (single self-contained .exe).
REM
REM  Requirements (MSYS2 MinGW-w64): g++, objcopy, windres.
REM
REM  ngram_quad.bin is included in this repository, so a normal build needs
REM  neither Python nor any external data file. If the binary is missing it is
REM  regenerated from the included english_quadgrams.txt (raw quadgram
REM  frequencies from Colossus, https://github.com/stblake/colossus), which
REM  requires Python 3.
REM
REM  To regenerate the table manually:
REM      python tools\gen_ngram_bin.py english_quadgrams.txt ngram_quad.bin
REM ===========================================================================
setlocal

if not exist ngram_quad.bin (
    if not exist english_quadgrams.txt (
        echo ERROR: ngram_quad.bin not found and english_quadgrams.txt is missing.
        echo Provide english_quadgrams.txt in the project root, or run:
        echo     python tools\gen_ngram_bin.py ^<quadgrams.txt^> ngram_quad.bin
        exit /b 1
    )
    echo [prep] ngram_quad.bin missing; generating from english_quadgrams.txt...
    python tools\gen_ngram_bin.py english_quadgrams.txt ngram_quad.bin || goto :err
)

echo [1/3] Embedding quadgram table...
objcopy -I binary -O pe-x86-64 -B i386:x86-64 ngram_quad.bin ngram_quad.o || goto :err

echo [2/3] Compiling resources...
windres playfair_breaker.rc -O coff -o playfair_breaker.res || goto :err

echo [3/3] Compiling and linking...
g++ -O3 -std=c++17 -municode -mwindows -o PlayfairBreaker.exe ^
    playfair_breaker.cpp ngram_quad.o playfair_breaker.res ^
    -lcomctl32 -lcomdlg32 -lgdi32 -luser32 -lshell32 -lole32 || goto :err

echo.
echo Build OK: PlayfairBreaker.exe
exit /b 0

:err
echo.
echo BUILD FAILED.
exit /b 1