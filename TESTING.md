# Testing Guide

This project uses pytest for automated testing.

## Running Tests

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run all tests
```bash
pytest test_app.py -v
```

### Run specific test class
```bash
pytest test_app.py::TestChores -v
```

### Run specific test
```bash
pytest test_app.py::TestChores::test_create_chore -v
```

### Run with coverage
```bash
pytest test_app.py --cov=main --cov-report=html
```

## Test Structure

The test suite is organized into the following test classes:

- **TestAuthentication**: Tests for user login, logout, and authentication
- **TestRooms**: Tests for room management (create, view, delete)
- **TestChores**: Tests for chore management (create, complete, delete)
- **TestLeaderboard**: Tests for leaderboard functionality and filtering
- **TestDashboard**: Tests for dashboard display
- **TestItems**: Tests for food items functionality
- **TestPointCalculation**: Tests for point calculation logic (early/on-time/late completion)
- **TestChoreCompletions**: Tests for completion tracking

## Test Coverage

The test suite covers:
- ✅ User authentication and authorization
- ✅ Room CRUD operations
- ✅ Chore CRUD operations  
- ✅ Chore completion with point calculation
- ✅ Point allocation based on completion timing (on-time, early, late)
- ✅ Leaderboard generation and filtering (monthly, all-time, custom range)
- ✅ Dashboard display
- ✅ Authentication requirements for protected routes

## Writing New Tests

When adding new functionality:
1. Create new test methods in the appropriate test class
2. Use the `client` fixture for unauthenticated tests
3. Use the `authenticated_client` fixture for tests requiring authentication
4. Follow the AAA pattern: Arrange, Act, Assert
5. Use descriptive test names starting with `test_`
