/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Envato authentication strategy authenticates requests by delegating to
 * Envato using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Envato application's Client ID
 *   - `clientSecret`  your Envato application's Client Secret
 *   - `callbackURL`   URL to which Envato will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'public_repo', 'repo', 'gist', or none.
 *                     (see http://developer.Envato.com/v3/oauth/#scopes for more info)
 *   — `userAgent`     All API requests MUST include a valid User Agent string. 
 *                     e.g: domain name of your application.
 *                     (see http://developer.Envato.com/v3/#user-agent-required for more info)
 *
 * Examples:
 *
 *     passport.use(new EnvatoStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/envato/callback',
 *         userAgent: 'myapp.com'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://api.envato.com/authorization';
  options.tokenURL = options.tokenURL || 'https://api.envato.com/token';
  // options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};
  
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-envato';
  }
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'envato';
  this._userProfileURL = options.userProfileURL || 'https://api.envato.com/v1/market/private/user/account.json';
  this._userProfileUsername = options.userProfileUsername || 'https://api.envato.com/v1/market/private/user/username.json';
  this._userProfileEmail = options.userProfileEmail || 'https://api.envato.com/v1/market/private/user/email.json';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Envato.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var _this = this;
  _this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'envato' };
      profile.image = json.account.image;
      profile.firstname = json.account.firstname;
      profile.surname = json.account.surname;
      profile.available_earnings = json.account.available_earnings;
      profile.total_deposits = json.account.total_deposits;
      profile.balance = json.account.balance;
      profile.country = json.account.country;
      
      profile._raw = body;
      profile._json = json;

      _this._oauth2.get(_this._userProfileUsername, accessToken, function (err, body, res) {
        if (err) { return done(new InternalOAuthError('failed to fetch username', err)); }
        try {
          var json = JSON.parse(body);
          profile.username = json.username;

          _this._oauth2.get(_this._userProfileEmail, accessToken, function (err, body, res) {
            if (err) { return done(new InternalOAuthError('failed to fetch email', err)); }

            try {
              var json = JSON.parse(body);
              profile.email = json.email;


              done(null, profile);
            } catch(e) {
              done(e);
            }
          });

        } catch(e) {
          done(e);
        }
      });

    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
