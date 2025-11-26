#!/bin/sh
set -x

# Integration test suite for lfe-sh

# Function to run a test and check its output
run_test() {
    test_name="$1"
    command="$2"
    expected_output="$3"

    echo "Running test: $test_name"
    # Use eval to handle commands with quotes and pipes correctly
    output=$(eval echo \"$command\" | ./lfe-sh)

    # Trim trailing newline from output for comparison
    output_trimmed=$(echo "$output" | tr -d '\n')

    if [ "$output_trimmed" = "$expected_output" ]; then
        echo "  [PASS]"
    else
        echo "  [FAIL]"
        echo "    Command: '$command'"
        echo "    Expected: '$expected_output'"
        echo "    Got: '$output_trimmed'"
        exit 1
    fi
}

# 1. Test Simple Command Execution
run_test "Simple Command" "ls README.md" "README.md"

# 2. Test Pipeline Execution
run_test "Pipeline" "echo 'hello world' | grep hello" "hello world"

# 3. Test Output Redirection
echo "Running test: Output Redirection"
# Run command to redirect output
echo 'echo "hello redirect" > redirect_test.txt' | ./lfe-sh
# Check if file was created and has the correct content
if [ -f "redirect_test.txt" ]; then
    content=$(cat redirect_test.txt)
    if [ "$content" = "hello redirect" ]; then
        echo "  [PASS]"
    else
        echo "  [FAIL]"
        echo "    File content was: '$content'"
        exit 1
    fi
else
    echo "  [FAIL]"
    echo "    File 'redirect_test.txt' was not created."
    exit 1
fi
rm redirect_test.txt


# 4. Test Append Output Redirection
echo "Running test: Append Output Redirection"
echo 'echo "line1" > append_test.txt' | ./lfe-sh
sleep 1
echo 'echo "line2" >> append_test.txt' | ./lfe-sh
if ! grep "line1" append_test.txt > /dev/null || ! grep "line2" append_test.txt > /dev/null; then
    echo "  [FAIL]: File content is incorrect."
    cat append_test.txt
    exit 1
fi
line_count=$(wc -l < append_test.txt | tr -d ' ')
if [ "$line_count" -ne 2 ]; then
    echo "  [FAIL]: Expected 2 lines, got $line_count."
    exit 1
fi
echo "  [PASS]"
rm append_test.txt

# 5. Test Input Redirection
echo "Running test: Input Redirection"
echo "hello input" > input_test.txt
output=$(echo 'grep hello < input_test.txt' | ./lfe-sh)
output_trimmed=$(echo "$output" | tr -d '\n')
if [ "$output_trimmed" = "hello input" ]; then
    echo "  [PASS]"
else
    echo "  [FAIL]"
    echo "    Command output was: '$output_trimmed'"
    exit 1
fi
rm input_test.txt


echo "\nAll shell tests passed!"
exit 0
