# API Endpoint Tests

# Test Chunk 1 - Account Management

## /api/v1/user/create
- Function: `createUserHandler` in `account.go`
- Potential errors: Invalid email, Invalid username, Username already exists, Failed to send magic link email

## /api/v1/user/finalize
- Function: `finalizeUserHandler` in `account.go`
- Potential errors: Invalid username, Missing password or token, Invalid or expired finalization token, Failed to process password, Failed to create user

## /api/v1/user/login
- Function: `loginUserHandler` in `account.go`
- Potential errors: Invalid username, Missing password, Invalid credentials, Internal server error (JWT signing failure)

## /api/v1/user/account/{SESSION-UUID}/bump
- Function: `bumpSessionHandler` in `session.go`
- Potential errors: Session not found, Internal server error, Session has expired, Session does not need to be bumped yet, Failed to update session, Failed to generate new session token

## /api/v1/user/account/{SESSION-UUID}/logout
- Function: `logoutHandler` in `session.go`
- Potential errors: Failed to logout, Session not found

## /api/v1/user/account/{SESSION-UUID}/read
- Function: `readAccountHandler` in `account.go`
- Potential errors: User ID not found in context, User not found, Failed to retrieve user data, Failed to encode response

## /api/v1/user/account/{SESSION-UUID}/update
- Function: `updateAccountHandler` in `account.go`
- Potential errors: User ID not found in context, Invalid request body, User not found, Invalid email, Failed to process new password, Failed to update user

## /api/v1/user/account/{SESSION-UUID}/delete
- Function: `deleteAccountHandler` in `account.go`
- Potential errors: User ID not found in context, Invalid request body, User not found, Invalid password, Failed to delete user sessions, Failed to delete user vouchers, Failed to delete user, Failed to commit changes


# TEST CHUNK 2 - KVS


## /api/v1/user/kv/{SESSION-UUID}/read/{KEY}
- Function: `kvReadHandler` in `kvs.go`
- Potential errors: User ID not found in context, Key not found, Failed to retrieve key-value pair

## /api/v1/user/kv/{SESSION-UUID}/write/{KEY}/{VALUE}
- Function: `kvWriteHandler` in `kvs.go`
- Potential errors: User ID not found in context, Failed to update key-value pair, Failed to create key-value pair, Database error, Maximum number of key-value pairs reached

## /api/v1/user/kv/{SESSION-UUID}/clear/
- Function: `kvClearHandler` in `kvs.go`
- Potential errors: User ID not found in context, Failed to clear key-value pairs

# Test Chunk 3 - Vouchers

## /api/v1/user/voucher/{SESSION-UUID}/create
- Function: `createVoucherHandler` in `vouchers.go`
- Potential errors: User ID not found in context, Invalid voucher lifetime, Voucher lifetime exceeds maximum allowed, Failed to read request body, User data exceeds 64 bytes limit, Failed to check voucher count, Maximum number of vouchers reached, Failed to create voucher

## /api/v1/user/voucher/{SESSION-UUID}/read
- Function: `readVouchersHandler` in `vouchers.go`
- Potential errors: User ID not found in context, Failed to retrieve vouchers, Failed to encode response

## /api/v1/user/voucher/{SESSION-UUID}/delete
- Function: `deleteVoucherHandler` in `vouchers.go`
- Potential errors: User ID not found in context, Voucher ID is required, Voucher not found or does not belong to the user, Failed to retrieve voucher, Failed to delete voucher

## /api/v1/voucher/authenticate
- Function: `authenticateVoucherHandler` in `vouchers.go`
- Potential errors: Voucher ID is required, Invalid voucher, Internal server error, Voucher has expired
