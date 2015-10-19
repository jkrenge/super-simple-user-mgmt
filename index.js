var Mongoose = require('mongoose');
var Schema = Mongoose.Schema;

var Bcrypt = require('bcrypt');
var Validator = require('validator');
var Async = require('async');

var User = new Schema({
  email: String,
  password: String,
  token: String,
  prototoken: String,
  expiration: Date,
  name: String
});

/**
 * register a user from a json object
 * @param  {Object/JSON}  json        Object with registration details:
 *                                    {
 *                                    	email: String (required),
 *                                    	password: String (required),
 *                                    	prototoken: String (optional),
 *                                    	name: String (optional)
 *                                    }
 * @param  {Function}     finished    callback(error, user)
 */
User.statics.register = function register(json, finished) {

  // required as reference for functions within our waterfall
  var UserClass = this;

  // do several function after each other to prepare user to be saved
  Async.waterfall([

    // waterfall #1: first we want to check whether we are extending a protoUser
    function checkForExtensionOfProtoUser(callback) {

      // this is likely, if we have the json key 'prototoken'
      if (json.hasOwnProperty('prototoken')) {

        // check for the protoUser
        UserClass.findOne({
          prototoken: json.prototoken
        }, function(error, protoUser) {

          if (error) finished(new Error("prototoken not valid"), null);
          else {

            if (protoUser) {

              // protoUser found, pass this to the next function
              callback(null, protoUser);

            } else callback(null, new UserClass());

          }
        });

      } else {

        // there is no protoUser, so just pass a new, empty user
        callback(null, new UserClass());

      }
    },

    // waterfall #1.1: if no protoUser was retrieved, create a new user
    function createUserIfNeeded(user, callback) {

      if (user === null) callback(null, new UserClass());
      else callback(null, user);

    },

    // waterfall #2: check the email
    function checkEmail(user, callback) {

      // is it even an email?
      if (Validator.isEmail(json.email)) {

        // only allow email if it is unique in the database
        UserClass.findOne({
          email: json.email
        }, function(error, emailUser) {

          if (error) callback(new Error("Error working on user database"), user);
          else {

            if (emailUser) callback(new Error("Email is already taken"), user);
            else {

              // email is okay, so save it to the user and forward the user to the next function
              user.email = json.email;
              callback(null, user);

            }
          }
        });

      } else callback(new Error("Email invalid"), user);
    },

    // waterfall #3: work with the password
    function checkPassword(user, callback) {

      // TODO: some useful checks if password is secure
      var isAlphanumeric = Validator.isAlphanumeric(json.password);

      // hash the password with bcrypt
      if (isAlphanumeric) {
        Bcrypt.genSalt(10, function(err, salt) {
          Bcrypt.hash(json.password, salt, function(err, hash) {

            // hashing complete, save it to the user and again, pass the user
            user.password = hash;
            callback(null, user);

          });
        });

      } else callback(new Error("Password not valid"), user);
    },

    // waterfall #4: we immediatly generate a token for the user
    function generateToken(user, callback) {

      // bcrypt does the job
      Bcrypt.genSalt(10, function(err, salt) {
        Bcrypt.hash(user._id.toString() + (new Date()).toString() + user.hash, salt, function(err, hash) {

          // update the user, then pass it onward
          user.token = hash;
          callback(null, user);

        });
      });

    },

    // waterfall #5: for security reasons, we invalidate the prototoken, which wasn't save to begin with
    function invalidatePrototoken(user, callback) {

      // same procedure as every year, james
      user.prototoken = null;
      callback(null, user);

    },

    // waterfall #7: save the non-critical user information, e.g. name

    function saveUserDetails(user, callback) {

      user.name = json.name;

      callback(null, user);

    }

    // ready with the waterfall
  ], function allChecked(error, user) {

    if (error) {
      finished(error, null);

    } else {

      // now we need to store the user, and if this was successfull return it to the callback
      user.save(function(err) {
        if (err) finished(err, null);
        else finished(null, user);
      });

    }
  });
};

/**
 * register an unidentified user (so called protouser) using an unique token, e.g. generated from hardware id
 * @param  {Object/JSON}  json        object with attribute 'prototoken'
 * @param  {Function}     finished    callback(error, user)
 */
User.statics.registerProto = function registerProto(json, finished) {

  // we just need the prototoken provided
  if (json.hasOwnProperty('prototoken')) {

    // new user, then assign the prototoken
    var user = new this();
    user.prototoken = json.prototoken;

    // save and return our protoUser
    user.save(function(err) {
      if (err) finished(err, null);
      else finished(null, user);
    });

  } else finished(new Error("Proto-User cannot be created without prototoken"), null);

};

/**
 * authenticates a user with credentials or prototoken
 * @param  {Object/JSON}  json        json object with credentials to be used for auth
 * @param  {Function}     finished    callback(error, user)
 */
User.statics.authenticate = function authenticate(json, finished)  {

  // first and most likely auth via email and token
  if (json.hasOwnProperty('token') && json.hasOwnProperty('user')) {

    // check for the user in the db via email
    this.findOne({
      email: json.user
    }, function(error, user) {

      if (error) finished(new Error("Problem with the database"), null);
      else {
        if (user) {

          // check whether the token matches
          if (user.token === json.token) finished(null, user);
          else finished(new Error("Invalid token"), null);

        } else finished(new Error("User does not exist"), null);
      }
    });

    // second strategy works for protoUser on the prototoken
  } else if (json.hasOwnProperty('prototoken')) {

    // find the user via the prototoken
    this.findOne({
      prototoken: json.prototoken
    }, function(error, user) {

      // there's no further check, if you have the prototoken, you're in
      if (error) finished(new Error("Problem with the database"), null);
      else {
        if (user) finished(null, user);
        else finished(new Error("prototoken not valid"), null);
      }

    });

    // third strategy works on email and the plan password
  } else if (json.hasOwnProperty('user') && json.hasOwnProperty('password')) {

    // again, find user via email
    this.findOne({
      email: json.user
    }, function(error, user) {

      if (error) finished(new Error("Problem with the database"));
      else {

        // if we have the user in the database, check the password
        if (user) {
          Bcrypt.compare(json.password, user.password, function(err, res) {
            if (res) {

              // we want to create a user token if there's none yet for login purpose
              if (user.token === null) {
                Bcrypt.genSalt(10, function(err, salt) {
                  Bcrypt.hash(user._id.toString() + (new Date()).toString() + user.hash, salt, function(err, hash) {
                    // we have a token now, but we also need to save it
                    user.token = hash;
                    user.save(function(err) {
                      // this is callback hell
                      if (err) finished(err, null);
                      else finished(null, user);
                    });
                  });
                });
              } else finished(null, user);

            } else finished(new Error("Password incorrect"), null);
          });
        } else finished(new Error("User does not exist"), null);

      }
    });

  } else finished(new Error("No valid authentication information submitted"), null);

};

/**
 * log out as a user user manually
 * @param  {Object/JSON}  json        authentiction json object like for auth()
 * @param  {Function}     finished    callback(error, user)
 */
User.statics.logout = function logout(json, finished) {

  this.authenticate(json, function(error, user) {

    if (error) finished(new Error("Logout failed: " + error.toString()), null);
    else {

      user.token = null;
      user.save(function(err) {
        if (err) finished(new Error("Logout failed: " + err.toString()), null);
        else finished(null, user);
      });

    }

  });

};

module.exports = Mongoose.model('User', User);
