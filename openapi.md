# Authorization Microservice

> Version 1.0.0

Authorization microservice for medical consultation application. Handles the authorization of users for the entire application.

## Path Table

| Method | Path | Description |
| --- | --- | --- |
| POST | [/login](#postlogin) | User Login |
| POST | [/logout](#postlogout) | User Logout |
| POST | [/users](#postusers) | Create User |
| POST | [/users/change-password](#postuserschange-password) | Change user password |
| GET | [/users/{id}](#getusersid) | Retrieve user information |
| PUT | [/users/{id}](#putusersid) | Update user information |
| GET | [/validate](#getvalidate) | Validates the user's token. |

## Reference Table

| Name | Path | Description |
| --- | --- | --- |
| ServerError | [#/components/responses/ServerError](#componentsresponsesservererror) | Server error |
| User | [#/components/schemas/User](#componentsschemasuser) | Schema for the User model, including fields for unique ID, email, password, role, and optional associations with patient and clinic. |
| cookieAuth | [#/components/securitySchemes/cookieAuth](#componentssecurityschemescookieauth) |  |

## Path Details

***

### [POST]/login

- Summary  
User Login

- Description  
Authenticates a user with their email and password.

#### RequestBody

- application/json

```ts
{
  // The user's unique email.
  email: string
  // The user's password.
  password: string
}
```

#### Responses

- 200 Successful login

`application/json`

```ts
{
  message?: string
}
```

- 401 Unauthorized - invalid credentials

`application/json`

```ts
{
  message?: string
}
```

- 500 undefined

***

### [POST]/logout

- Summary  
User Logout

- Description  
Logs out a user by clearing authentication tokens.

#### Responses

- 200 Successful logout

`application/json`

```ts
{
  message?: string
}
```

- 401 Unauthorized - user is not logged in

`application/json`

```ts
{
  message?: string
}
```

- 500 undefined

***

### [POST]/users

- Summary  
Create User

- Description  
Creates a new user with specified roles, email, and associated IDs for doctor or patient.

- Security  
cookieAuth  

#### RequestBody

- application/json

```ts
{
  // Email address of the user.
  email: string
  // User's password.
  password: string
  roles?: string[]
  // Unique ID if the user is a doctor.
  doctorid?: string
  // Unique ID if the user is a patient.
  patientid?: string
}
```

#### Responses

- 201 User created successfully

`application/json`

```ts
{
  email?: string
  roles?: string[]
  doctorid?: string
  patientid?: string
}
```

- 400 Bad request - missing fields or user already exists

`application/json`

```ts
{
}
```

- 401 Unauthorized - token missing or invalid

`application/json`

```ts
{
  message?: string
}
```

- 403 Forbidden - insufficient permissions

`application/json`

```ts
{
  message?: string
}
```

- 500 undefined

***

### [POST]/users/change-password

- Summary  
Change user password

- Description  
Allows authenticated users to change their password.

#### RequestBody

- application/json

```ts
{
  // The current password of the user.
  currentPassword: string
  // The new password to set.
  newPassword: string
}
```

#### Responses

- 200 Password changed successfully

`application/json`

```ts
{
  message?: string
}
```

- 400 Invalid request

`application/json`

```ts
{
  message?: string
}
```

- 401 Unauthorized

`application/json`

```ts
{
  message?: string
}
```

- 403 Unauthorized access

`application/json`

```ts
{
  message?: string
}
```

- 404 User not found

`application/json`

```ts
{
  message?: string
}
```

- 500 Internal server error

`application/json`

```ts
{
  message?: string
}
```

***

### [GET]/users/{id}

- Summary  
Retrieve user information

- Description  
Retrieve user details by user ID. Requires the user to be the owner or have specific roles.

#### Responses

- 200 User retrieved successfully

`application/json`

```ts
{
  _id?: string
  email?: string
  username?: string
  roles?: string[]
  createdAt?: string
  updatedAt?: string
}
```

- 401 Unautenticated

`application/json`

```ts
{
  message?: string
}
```

- 403 Unauthorized access

`application/json`

```ts
{
  message?: string
}
```

- 404 User not found

`application/json`

```ts
{
  message?: string
}
```

- 500 Internal server error

`application/json`

```ts
{
  message?: string
}
```

***

### [PUT]/users/{id}

- Summary  
Update user information

- Description  
Update user details by user ID. Requires the user to be the owner or have specific roles.

#### RequestBody

- application/json

```ts
{
  // Email address of the user.
  email?: string
  // User's password.
  password?: string
  roles?: string[]
}
```

#### Responses

- 200 User updated successfully

`application/json`

```ts
{
  _id?: string
  email?: string
  roles?: string[]
  createdAt?: string
  updatedAt?: string
}
```

- 400 Bad request - missing fields or user already exists

`application/json`

```ts
{
}
```

- 401 Unautenticated

`application/json`

```ts
{
  message?: string
}
```

- 403 Unauthorized access

`application/json`

```ts
{
  message?: string
}
```

- 404 User not found

`application/json`

```ts
{
  message?: string
}
```

- 500 Internal server error

`application/json`

```ts
{
  message?: string
}
```

***

### [GET]/validate

- Summary  
Validates the user's token.

- Description  
Checks the validity of the token provided in the user's cookies.

#### Responses

- 200 Token is valid.

`application/json`

```ts
{
  message?: string
}
```

- 401 Unauthorized - Token is missing, expired, or invalid.

`application/json`

```ts
{
  message?: string
}
```

## References

### #/components/responses/ServerError

- application/json

```ts
{
  message?: string
}
```

### #/components/schemas/User

```ts
// Schema for the User model, including fields for unique ID, email, password, role, and optional associations with patient and clinic.
{
  // Unique identifier for the user. Defaults to a generated UUID.
  _id?: string
  // Unique email for the user.
  email: string
  // Hashed password of the user.
  password: string
  roles?: enum[admin, clinicadmin, doctor, patient][]
  // Identifier of the doctor if the user is a clinic doctor.
  doctorid?: string
  // Identifier of the patient if the user is associated with a patient record.
  patientid?: string
  // Timestamp when the user was created.
  createdAt?: string
  // Timestamp when the user was last updated.
  updatedAt?: string
}
```

### #/components/securitySchemes/cookieAuth

```ts
{
  "type": "apiKey",
  "in": "cookie",
  "name": "token"
}
```