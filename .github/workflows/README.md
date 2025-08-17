# ConnectedHomeIP YAML Integration Tests

This directory contains the GitHub Actions workflow for running rs-matter against the ConnectedHomeIP YAML test suite.

## Overview

The `connectedhomeip-tests.yml` workflow runs nightly and can be triggered manually to validate rs-matter compatibility with the official Matter test cases from the ConnectedHomeIP project.

## Workflow Features

- **Nightly execution**: Runs automatically every night at 2:00 AM UTC
- **Manual triggering**: Can be invoked manually via GitHub's workflow_dispatch
- **Configurable tests**: Easy to enable/disable specific tests by commenting/uncommenting
- **Caching**: Uses GitHub Actions cache for both ConnectedHomeIP builds and Rust dependencies
- **Artifact collection**: Uploads test results and logs on failure for debugging

## Test Management

The workflow is designed to support an iterative approach to test enablement:

### Currently Enabled Tests
- `TestAttributesById` - Tests attribute access by ID

### Currently Disabled Tests (Available for Enablement)
- `TestAccessControlCluster` - Tests access control functionality
- `TestBasicInformation` - Tests basic device information cluster

### How to Enable/Disable Tests

Tests can be easily enabled or disabled by editing the workflow file manually:

1. Open `.github/workflows/connectedhomeip-tests.yml`
2. Find the "Run YAML Integration Tests" step
3. Locate the test you want to enable/disable in the comments
4. To **enable** a test: Remove the `#` comment characters from both the echo and test command lines
5. To **disable** a test: Add `#` comment characters to both the echo and test command lines

Example:
```yaml
# DISABLED TEST:
# echo "Running TestAccessControlCluster..."
# ${CHIP_HOME}/scripts/run_in_build_env.sh \
#   "${CHIP_HOME}/scripts/tests/run_test_suite.py \
#   --log-level warn --target TestAccessControlCluster \
#   ...rest of command"

# ENABLED TEST:
echo "Running TestAccessControlCluster..."
${CHIP_HOME}/scripts/run_in_build_env.sh \
  "${CHIP_HOME}/scripts/tests/run_test_suite.py \
  --log-level warn --target TestAccessControlCluster \
  ...rest of command"
```

**Important**: Make sure to uncomment/comment ALL lines belonging to a test (both the echo statement and the full test command which may span multiple lines).

### Adding New Tests

To add a new test:

1. Follow the pattern shown in the workflow file
2. Add both an echo statement and the test execution command
3. Initially add the test in commented form for review
4. Test locally or in a PR before enabling in the main branch

Example format:
```yaml
# New Test Example
# echo "Running TestNewCluster..."
# ${CHIP_HOME}/scripts/run_in_build_env.sh "${CHIP_HOME}/scripts/tests/run_test_suite.py --log-level warn --target TestNewCluster --runner chip_tool_python --chip-tool ${CHIP_HOME}/out/host/chip-tool run --iterations 1 --test-timeout-seconds 120 --all-clusters-app ${RS_MATTER}/target/debug/examples/onoff_light --lock-app ${RS_MATTER}/target/debug/examples/onoff_light"
```

## Test Categories

Tests are organized by priority:

1. **System/Utility Clusters** (Current focus)
   - Access Control
   - Basic Information  
   - General Diagnostics
   - Network Commissioning
   - etc.

2. **Application Clusters** (Future focus)
   - OnOff
   - Level Control
   - Color Control
   - etc.

## Manual Execution

To run the workflow manually:

1. Go to the Actions tab in the GitHub repository
2. Select "ConnectedHomeIP YAML Integration Tests"
3. Click "Run workflow"
4. Optionally specify a different ConnectedHomeIP branch/commit
5. Click "Run workflow" to start

## Troubleshooting

If tests fail:

1. Check the workflow logs in the GitHub Actions tab
2. Download the uploaded artifacts which contain:
   - Test output logs
   - rs-matter temporary data
   - chip-tool logs
3. Look for specific test failures and error messages
4. Compare with the original shell script (`chip-tool-tests.sh`) for reference

## Development Workflow

1. When a test fails, create an issue describing the failure
2. Developers fix the issue in rs-matter
3. Once fixed, the test should pass in subsequent runs
4. Continue enabling more tests iteratively
5. The goal is to eventually pass all Matter utility/system cluster tests