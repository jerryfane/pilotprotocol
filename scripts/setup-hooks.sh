#!/bin/bash

# Setup git hooks for Pilot Protocol
# Run this script after cloning the repository

HOOKS_DIR=".git/hooks"
PRE_COMMIT_HOOK="$HOOKS_DIR/pre-commit"
PRE_PUSH_HOOK="$HOOKS_DIR/pre-push"

echo "Setting up git hooks..."

# Check if .git directory exists
if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run this from the project root."
    exit 1
fi

# Create pre-commit hook
cat > "$PRE_COMMIT_HOOK" << 'EOF'
#!/bin/sh

# Pre-commit hook for Pilot Protocol
# Runs go fmt, go vet, tests, and updates coverage

echo "Running pre-commit checks..."

# 1. Format code
echo "→ Running go fmt..."
if ! gofmt -w -s .; then
    echo "✗ go fmt failed"
    exit 1
fi

# 2. Vet code
echo "→ Running go vet..."
if ! go vet ./...; then
    echo "✗ go vet failed"
    exit 1
fi

# 3. Run tests
echo "→ Running tests..."
if ! (cd tests && go test -timeout 30s > /tmp/pilot-test.log 2>&1); then
    echo "✗ tests failed - see /tmp/pilot-test.log for details"
    tail -20 /tmp/pilot-test.log
    exit 1
fi
echo "✓ tests passed"

# 4. Update coverage
echo "→ Updating coverage badge..."
if ! make coverage > /dev/null 2>&1; then
    echo "✗ coverage generation failed"
    exit 1
fi

# Stage any changes from gofmt and coverage
git add -A

echo "✓ All pre-commit checks passed"
exit 0
EOF

# Make hook executable
chmod +x "$PRE_COMMIT_HOOK"

# Install repo-managed pre-push hook.
ln -sf ../../scripts/git-hooks/pre-push "$PRE_PUSH_HOOK"
chmod +x scripts/git-hooks/pre-push

echo "✓ Git hooks installed successfully!"
echo ""
echo "The pre-commit hook will run on every commit and check:"
echo "  - Code formatting (go fmt)"
echo "  - Static analysis (go vet)"
echo "  - Tests (go test)"
echo "  - Coverage badge update"
echo ""
echo "To skip the hook temporarily, use: git commit --no-verify"
echo ""
echo "The pre-push hook will run before every push and check:"
echo "  - Full Go package tests, excluding the manual dashboard package"
echo ""
echo "To skip the pre-push hook temporarily, use: git push --no-verify"
