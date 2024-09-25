# Yokel

## O'hey'der

Hows it goin buhd?

This here is the backend for the o'hey'der'bud site.

```
Usage:
    --install <PATH>               Install the server onto the system in a specific directory
                                       - Path must not exist yet; yokel will create subdirectory: "log"
                                       - Yokel will also create a default "yokel.yaml" This configuration, if given a valid "key" and "cert" field will force https, but they are not required (http will be used if not set)
                                           Other values such as "port" "binding" and "url" will also be included (more below)

    --up      <PATH>               Attempt to start a server based on the yaml configuration found in "/your/install/yokel.yaml"
                                       - Attempts to load and configure the server as-per the configuration in the yokel yaml (sometimes mentiond as y2 because yy yanks and "yokel yaml" takes to darn long to type)

    --down    <PATH>               Will use the "yokel.pid" if it exists to see if the yokel process is running. If it is, then it kills the server and removes the pid file

    --restart <PATH>               Just does the same as "--down --up" along with a momentary (1 sec) pause between the commands
```


## API 

### HTTP UV-Buhd v1

The UV-Buhd v1 api does the following:
    Allows the creation and management of a "user" account. This might be a human, or just a password protected object. Doesn't really matter.
    The "user" is associated with a  "settings" structure. The setting structure must be declared by the host (driver) application that uses this library.
    In this way Yokel attempts to be some abstract "user" authentication service thats easily reusable.
And More!:
    This API also has a concept of "vouchers" or "pre-authenticated, encrypted, data resources.
    It allows a "user" to pre-authenticate some request for a given amount of time.
        the voucher can contain up-to 64 bytes of user-data, 
    This data is stored in the server for the duration of the given lifetime, and can be read/authenticated regardless if the user is logged in
        via the "voucher/authenticate" endpoint.

CORS Policy:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, Yokel-API-Version-1, Yokel-Email, Yokel-Username, Yokel-Password, Yokel-Finalization-Token, Yokel-Session-Token, Yokel-Voucher-Lifetime, Yokel-User-Voucher
Access-Control-Expose-Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
Access-Control-Allow-Credentials: false
Access-Control-Max-Age: 3600
```


```

    All endpoints below MUST include HTTP Header "Yokel-API-Version-1". 
    All requirements listed below prefixed with "Yokel-" must be in the header section of the corresponding HTTP request.
    The description on the right is the description of the entire endpoint that it is in-line with.


    Endpoint              Method     Access         Requires                         Description

    /api/v1/user/create   
                            POST     PUBLIC         Yokel-Email                    Attempt to create a new user (username must be unique.)
                                                    Yokel-Username                 An email containing a magic link will be sent to the user to confirm the address.
                                                                                   That link will contain a 5 minute JWT token mapped to the username.
                                                                                   That JWT will be used to "finalize" a user, which is when their password will be submitted.
                                                                                   If the user wants to store their email, an /account/update can be submitted with the email and
                                                                                   any other changes they want done.
                                                                                   If a user fails to finalize their account within the timespan of the JWT, this endpoint will need
                                                                                   to be called again.
                                                                        
    /api/v1/user/finalize
                            POST     PUBLIC         Yokel-Username                 The JWT must be present, valid, and mapped to the username internally to return success.
                                                    Yokel-Password                 This endpoint can be called while the JWT is valid.
                                                    Yokel-Finalization-Token

    /api/v1/user/login
                            POST     PUBLIC         Yokel-Username                 Attempt to log the user into the system. This endpoint is rate limited more than the others.
                                                    Yokel-Password                 If the username, password pair authenticate against the system a 200 will be sent containing a session UUID
                                                                                   (used in routes below) and a 30 minute JWT used to be used as 'Yokel-Session-Token' below.
                                                                                   All instances requiring the use of a session UUID and a JWT have the requirement of the JWT not being "expired"
                                                                                   AND it must map to an active UUID. This permits the cycling of JWTs per-UUID without having to store every
                                                                                   JWT internally if they wan to /bump their time (below.)
                                                                                        - Important note: The UUID is _not_ stored with any user. It is a temporary session id that, if it doesn't map
                                                                                            directly to a valid JWT it will be removed, logging the user out.


    /api/v1/user/account/{SESSION-UUID}/bump    
                            POST     RESTRICTED     Yokel-Session-Token            This will update the time left on the JWT if and only if the time remaining is < 5 minutes. If this is called
                                                                                   too frequently without success (> 5 times) then the session will be immediatly terminated. This means it is
                                                                                   very important not to leak session JWTs. 
                                                                                   On success, the current JWT will be made invalid, and a fresh 30-minute JWT will be issued for the account.

    /api/v1/user/account/{SESSION-UUID}/logout
                            POST    RESTRICTED      Yokel-Session-Token            Terminate the session if and only if the session JWT is valid (obviously) a


    /api/v1/user/account/{SESSION-UUID}/read
                            GET     RESTRICTED      Yokel-Session-Token            Retrieve the user structure of the user from the database (except the password)


    /api/v1/user/account/{SESSION-UUID}/update
                            POST    RESTRICTED      Yokel-Session-Token            Update the setting structure userfrom the database. (username, email, password, etc)
                                                    JSON-Body: User structure
                                                       returned by account/read

    /api/v1/user/account/{SESSION-UUID}/delete
                            DELETE    RESTRICTED      Yokel-Session-Token            Delete the account associated with the session. Requires valid password in body as well. All information
                                                    JSON-Body: password             directly relating to the user account details will be removed. Any meta-information elsewhere in the system
                                                                                    (if any) will not be explitly deleted by this endpoint though I don't intend on having any other type of "user data"
                                                                                    unless that counts "meta data." If thats the case, this version (v1) doesn't care, its not related.

    /api/v1/user/kv/{SESSION-UUID}/read/{KEY}
                            GET     RESTRICTED      Yokel-Session-Token            Store some key-value pairs for the user. Max KV pairs defined in yokel.yaml "user_data_max"
                                                                                   Note: if "no_kv" is set to true in the yokel.yaml file, this endpoint will not be available.

    /api/v1/user/kv/{SESSION-UUID}/write/{KEY}/{VALUE}
                            GET    RESTRICTED      Yokel-Session-Token            Store some key-value pairs for the user. Max KV pairs defined in yokel.yaml "user_data_max"
                                                                                   Note: if "no_kv" is set to true in the yokel.yaml file, this endpoint will not be available.

    /api/v1/user/kv/{SESSION-UUID}/clear/
                            DELETE RESTRICTED      Yokel-Session-Token           Clears all key-value pairs for the user.
                                                                                   Note: if "no_kv" is set to true in the yokel.yaml file, this endpoint will not be available.

    /api/v1/user/voucher/{SESSION-UUID}/create
                            POST    RESTRICTED      Yokel-Session-Token            Create a new voucher associated with the user's account. The voucher is similar to a JWT but it encodes information specific to a resource as well
                                                    Yokel-Voucher-Lifetime          as lifetime/ user info such-that a voucher can be used to authenticate any external request that the user has configured. The Voucher-lifetime
                                                                                    has to be a string representing the number of hours, or minutes in the form "1h5m" or "24m" etc.

                                                                                    If the request body exceeds 64 bytes, the request will fail. All of the 64 permitted bytes given to the body will be encoded into the voucher.
                                                                                        Note: This encoding is NOT cryptographically secure and it is not intended to be


                                                                                    The maximum lifetime of a voucher is defined in yokel.yaml "voucher_max_lifetime"
                                                                                    The maximum number of vouchers a user can have is defined in yokel.yaml "voucher_max_per_user"


    /api/v1/user/voucher/{SESSION-UUID}/read
                            GET     RESTRICTED      Yokel-Session-Token           Returns a list of ALL vouchers the user has created 
                                                                    

    /api/v1/user/voucher/{SESSION-UUID}/delete
                            DELETE    RESTRICTED      Yokel-Session-Token           Requires the voucher that they want to delete. This will erase the voucher and it will invalidate any request against it
                                                    Yokel-User-Voucher

    /api/v1/voucher/authenticate
                            GET     PUBLIC          Yokel-User-Voucher           Checks the user's voucher from the header. If its valid, it will decode the voucher and return whatever data they stored inside it.


```


User Structure:
```
{
    "username": "username",
    "email": "email",
    "password": "password",
}
```

Settings Structure:
```
{
    
}
```

# Configuration Options

The following options can be set in the `yokel.yaml` configuration file:

- `port`: The port number on which the server listens (default: 8080)
- `binding`: The IP address to bind the server to (default: "0.0.0.0")
- `url`: The base URL of the server (default: "http://localhost")
- `key`: Path to the SSL key file (optional)
- `cert`: Path to the SSL certificate file (optional)
- `voucher_max_lifetime`: Maximum lifetime of a voucher (default: "1h")
- `voucher_max_per_user`: Maximum number of vouchers per user (default: 5)
- `no_kv`: Disable the key-value store functionality (default: false)
- `user_data_max`: Maximum size of user data in bytes (default: 100)
- `jwt_secret_key`: Secret key used for JWT token signing and verification (automatically generated during installation)

Note: The `jwt_secret_key` is automatically generated during installation for security reasons. You can change it manually in the configuration file if needed, but make sure to keep it secret and use a strong, random value.
