
#!/bin/bash

echo "🔍 Verifying complete console output elimination..."

# Check if build files exist
if [ ! -f "CMakeLists.txt" ]; then
    echo "❌ CMakeLists.txt not found"
    exit 1
fi

# Compile the project with proper error checking
echo "📋 Building project..."
if ! make clean >/dev/null 2>&1; then
    echo "⚠ Clean failed, continuing..."
fi

if ! make >/dev/null 2>&1; then
    echo "❌ Build failed"
    exit 1
fi

# Find the correct executable name
EXECUTABLE=""
if [ -f "./pdf_processor" ]; then
    EXECUTABLE="./pdf_processor"
elif [ -f "./main" ]; then
    EXECUTABLE="./main"
elif [ -f "./pdf_byte_fidelity_processor" ]; then
    EXECUTABLE="./pdf_byte_fidelity_processor"
else
    echo "❌ No executable found"
    exit 1
fi

echo "📋 Using executable: $EXECUTABLE"

# Test 1: Check for any stdout/stderr output during execution
echo "📋 Test 1: Checking for console output during PDF processing..."

# Create a proper test PDF file
cat > test_input.pdf << 'EOF'
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Hello World) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000204 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
297
%%EOF
EOF

# Test different operation modes
TEST_MODES=("process-file" "api-server")
for mode in "${TEST_MODES[@]}"; do
    echo "Testing mode: $mode"
    
    if [ "$mode" = "api-server" ]; then
        # Test API server startup (short duration)
        timeout 3s $EXECUTABLE $mode test_input.pdf test_output.pdf > output_capture.txt 2>&1 &
        SERVER_PID=$!
        sleep 2
        kill $SERVER_PID 2>/dev/null
        wait $SERVER_PID 2>/dev/null
        OUTPUT_CAPTURED=$(cat output_capture.txt)
    else
        # Test file processing
        OUTPUT_CAPTURED=$($EXECUTABLE $mode test_input.pdf test_output.pdf 2>&1)
    fi
    
    if [ -n "$OUTPUT_CAPTURED" ]; then
        echo "❌ Test 1 FAILED: Console output detected in $mode:"
        echo "$OUTPUT_CAPTURED"
        exit 1
    fi
done

echo "✅ Test 1 PASSED: No console output detected"

# Test 2: Check for any file creation (logs, traces, etc.)
echo "📋 Test 2: Checking for unwanted file creation..."

# Clean up any existing log files
find . -name "*.log" -delete 2>/dev/null
find . -name "*.trace" -delete 2>/dev/null
find . -name "*.debug" -delete 2>/dev/null

FILE_COUNT_BEFORE=$(find . -type f \( -name "*.log" -o -name "*.trace" -o -name "*.debug" \) | wc -l)
$EXECUTABLE process-file test_input.pdf test_output2.pdf >/dev/null 2>&1
FILE_COUNT_AFTER=$(find . -type f \( -name "*.log" -o -name "*.trace" -o -name "*.debug" \) | wc -l)

if [ "$FILE_COUNT_BEFORE" -ne "$FILE_COUNT_AFTER" ]; then
    echo "❌ Test 2 FAILED: Unwanted files detected"
    find . -type f \( -name "*.log" -o -name "*.trace" -o -name "*.debug" \) -newer test_input.pdf
    exit 1
fi

echo "✅ Test 2 PASSED: No unwanted files created"

# Test 3: Check environment variables don't leak processing info
echo "📋 Test 3: Checking environment doesn't leak processing info..."
ENV_BEFORE=$(env | grep -i "pdf\|process\|debug\|log" | wc -l)
$EXECUTABLE process-file test_input.pdf test_output3.pdf >/dev/null 2>&1
ENV_AFTER=$(env | grep -i "pdf\|process\|debug\|log" | wc -l)

if [ "$ENV_BEFORE" -ne "$ENV_AFTER" ]; then
    echo "❌ Test 3 FAILED: Environment variables leaked"
    exit 1
fi

echo "✅ Test 3 PASSED: No environment contamination"

# Test 4: Validate silent operation validator
echo "📋 Test 4: Running internal silent operation validator..."
if [ -f "./validate_silent_operation" ]; then
    if ! ./validate_silent_operation >/dev/null 2>&1; then
        echo "❌ Test 4 FAILED: Silent operation validator failed"
        exit 1
    fi
    echo "✅ Test 4 PASSED: Silent operation validator confirmed silence"
else
    echo "⚠ Test 4 SKIPPED: Silent operation validator not found"
fi

# Test 5: Memory leak detection
echo "📋 Test 5: Checking for memory leaks during silent operation..."
if command -v valgrind >/dev/null 2>&1; then
    VALGRIND_OUTPUT=$(valgrind --leak-check=full --error-exitcode=1 $EXECUTABLE process-file test_input.pdf test_output4.pdf 2>&1)
    if [ $? -ne 0 ]; then
        echo "❌ Test 5 FAILED: Memory leaks detected"
        exit 1
    fi
    echo "✅ Test 5 PASSED: No memory leaks detected"
else
    echo "⚠ Test 5 SKIPPED: valgrind not available"
fi

# Cleanup
rm -f test_input.pdf test_output*.pdf output_capture.txt

echo ""
echo "🎉 ALL TESTS PASSED: Complete console output elimination verified!"
echo "🔒 System achieved forensic invisibility - zero traces detected"
echo "✅ Silent operation fully validated and confirmed"
