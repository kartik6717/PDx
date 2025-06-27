#!/bin/bash

# CI/CD Pipeline Output Check Script
# Detects any console output functions in the codebase

echo "Checking for console output violations..."

# Define patterns to search for
OUTPUT_PATTERNS=(
    "std::cout"
    "std::cerr"
    "std::clog"
    "printf("
    "fprintf("
    "puts("
    "fputs("
    "putchar("
    "fputc("
    "std::printf"
    "std::fprintf"
)

# Define files to exclude from checks
EXCLUDE_FILES=(
    "logger.cpp"
    "logger.hpp"
    "silent_operation_manager.cpp"
    "stream_suppression.cpp"
    "global_silence_enforcer.hpp"
    "complete_output_suppressor.hpp"
    "silent_operation_validator.hpp"
    "null_output_enforcer.cpp"
)

# Function to check if file should be excluded
should_exclude() {
    local file=$1
    for exclude in "${EXCLUDE_FILES[@]}"; do
        if [[ "$file" == *"$exclude" ]]; then
            return 0
        fi
    done
    return 1
}

VIOLATIONS=0

# Search for output patterns in all C++ files
for pattern in "${OUTPUT_PATTERNS[@]}"; do
    echo "Checking for: $pattern"
    
    # Find all C++ source files
    find . -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.h" -o -name "*.cc" \) | while read -r file; do
        # Skip excluded files
        if should_exclude "$file"; then
            continue
        fi
        
        # Check for pattern in file
        if grep -n "$pattern" "$file" > /dev/null 2>&1; then
            echo "VIOLATION: Found '$pattern' in $file:"
            grep -n "$pattern" "$file"
            ((VIOLATIONS++))
        fi
    done
done

# Check for file output operations
echo "Checking for file output operations..."
FILE_PATTERNS=(
    "std::ofstream"
    "fopen("
    "freopen("
)

for pattern in "${FILE_PATTERNS[@]}"; do
    find . -type f \( -name "*.cpp" -o -name "*.hpp" \) | while read -r file; do
        if should_exclude "$file"; then
            continue
        fi
        
        if grep -n "$pattern" "$file" | grep -v "/dev/null" | grep -v "NUL" > /dev/null 2>&1; then
            echo "VIOLATION: Found file output '$pattern' in $file:"
            grep -n "$pattern" "$file" | grep -v "/dev/null" | grep -v "NUL"
            ((VIOLATIONS++))
        fi
    done
done

if [ $VIOLATIONS -eq 0 ]; then
    echo "✅ No output violations found!"
    exit 0
else
    echo "❌ Found $VIOLATIONS output violations!"
    exit 1
fi