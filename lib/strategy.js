/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , lookup = require('./utils').lookup;


/**
 * `Strategy` constructor.
 *
 * The Rqsite access token authentication strategy authenticates requests based on the
 * credentials submitted through an ajax login post action.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `token` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `tokenField`  field name where the access token is found, defaults to _token_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new RqsiteStrategy(
 *       function(username, token, done) {
           UserService.findOne({ username: username, token: token }, function (err, user) {
             done(err, user);
           });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('RqsiteStrategy requires a verify callback'); }
  
  this._usernameField = options.usernameField || 'username';
  this._tokenField = options.tokenField || 'token';
  
  passport.Strategy.call(this);
  this.name = 'rqsite';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
  var token = lookup(req.body, this._tokenField) || lookup(req.query, this._tokenField);
  
  if (!username || !token) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  try {
    if (self._passReqToCallback) {
      this._verify(req, username, token, verified);
    } else {
      this._verify(username, token, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
