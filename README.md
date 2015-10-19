# Super Simple User Mgmt

```
API user management for mobile apps
```

A `mongoose` model to deal with super simple user management for APIs. By plugging this model into your API, you can allow users to register and authenticate for an API.

**Use case:** If you want to create a simple API to be used e.g. by an iPhone app, you can plug this model in your backend API to authenticate calls.

## Features and how it works

At the core, `super-simple-user-mgmt` is a Mongoose model called `User`:

```javascript
var User = new Schema({
  email: String,
  password: String,
  token: String,
  prototoken: String,
  name: String
});
```

`email`, `password` and `name` can be set on registration. Before full registration with info input by the user, a `User` can be created with a `prototoken`. The `password` is securely encrypted with [bcrypt](url).

## Setup

### Requirements

`super-simple-user-mgmt` requires an active and working  [MongoDB](url) connected through [Mongoose](url). If you don't have that yet, you can install MongoDB using their tutorial, and connect to it using this [recommended connection handling code](url).

### Install and require

Recommended way to install is via [npm](https://www.npmjs.com):

```sh
npm install --save super-simple-user-mgmt
```

Then simply require the module in your API, e.g. using [Express](url):

```javascript
var User = require('super-simple-user-mgmt');
```

All done. You now can manage your users as explained below.

## Usage

You can register as an unknown and unidentified user (so called `protouser`) or as a full fledged `user` with identification details. Why? A protouser can be registered by your (mobile) app when the user first opens it, so you can store all data with your normal structure in the backend, without asking the user for registration directly. This hopefully improves user experience and hence your conversion.

### Registration of protouser

If you want to store user-related data in your backend via an API, but don't want the user directly to register, you need a `protouser`.

For this, you only need one unique token or identifier generated by the app. For iPhone apps e.g. this could be:

```cocoa

```

You can create a route to register a protouser with [Express.js](url) like so:

```javascript
router.post('/registerProto', function(req, res) {

  User.registerProto({
    prototoken: req.body.prototoken
  }, callback(error, user) {
    if (error) // handle the error
    else // all good
  });

});
```

The user is registered, and can only identify itself using the same `prototoken` again. So the app needs to store it.

### Registration of full user

If you already have some details about the users identity (email and password), you can directly register a full user. This is done with `User.register(info, callback)`.

You pass the register an object with the user's information: `email` and `password` are required, you can also state a `name` of the user. By providing a `prototoken`, you can extend an existing `protouser` (see above).

```javascript
router.post('/register', function(req, res) {

  // read users info from req.body
  var info = {
    email: String (required),
    password: String (required),
    prototoken: String (optional),
    name: String (optional)
  };

  User.register(info, callback(error, user) {
    if (error) return error; // handle the error
    else {
      // return the users token via the API
      res.send(user.token);
    }
  });

});
```

This simple example with [Express.js](url) show the general workflow. The user is registered and logged in, you it is recommended to at least return the users `token`. But you can return anything, as the callback's `user` is the full object as described above.

By the way, the `prototoken`, if you had one, was invalidated.

### Authentication

An example for an [Express.js](url) route to authenticate a user is:

```javascript
router.post('/do-something', function(req, res) {
  User.authenticate(req.body.credentials, function(error, user) {
    if (error) // handle the error
    else // all good
  });
});
```

On a non-error callback, you have the full user object as described above.

The JSON object in `req.body.credentials` can hold credentials in three flavors:

#### 1. Prototoken

```json
{
  "prototoken": "an-unique-hardware-token"
}
```

Only the `prototoken`. Note that this only works for protousers.

#### 2. Username & password

```json
{
  "user": "users-email-address",
  "password": "users-password"
}
```

Normal auth via `user` and `password`. It is preferable to use rather the token as described below, so only use it if the token was invalidated.

#### 3. Username & token

```json
{
  "user": "users-email-address",
  "token": "users-token"
}
```

The user's `token`, but not the `prototoken`. This is the preferred way to auth every request to the API, so that the password is not submitted every time.

### All the rest

If required, a user can be logged out. This means, his `token` will be invalidated. This does not work for protousers.

```javascript
User.logout(info, function (error, user) {
  if (error) // handle the error
  else // all good
})
```

For a non-error callback, the var `user` now holds the whole user object, with its `token` set to `null`.

## Contribution

Fork, change, request a pull. Talk to me via issues or email.
