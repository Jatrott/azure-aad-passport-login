'use strict';
require('dotenv').config()

const restify = require('restify');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const expressSession = require('express-session');
const crypto = require('crypto');
const querystring = require('querystring');
//const https = require('https');
const request = require('request');


//oauth details
const AZUREAD_APP_ID = process.env.AZUREAD_APP_ID;
const AZUREAD_APP_PASSWORD = process.env.AZUREAD_APP_PASSWORD;
const AZUREAD_APP_REALM = process.env.AZUREAD_APP_REALM;
const AUTH_CALLBACKHOST = process.env.AUTH_CALLBACKHOST;
const AUTH_STRATEGY = process.env.AUTH_STRATEGY;

//=========================================================
// Server Setup
//=========================================================

// Setup Restify Server
var server = restify.createServer();
server.listen(process.env.port || process.env.PORT || 3979, function () {
  console.log('%s listening to %s', server.name, server.url); 
});
  
console.log('Started...')
var callbackURI = AUTH_CALLBACKHOST + '/auth/openid/return';
console.log('MY CALLBACK: ' + callbackURI);

//=========================================================
// Auth Setup
//=========================================================

server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));
server.use(passport.initialize());

server.get('/', 
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  function(req, res, next) {
    console.log('Root, has been served');
    res.write('I am (g)root');
    res.end();
    next();
});

server.get('/login', 
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  function(req, res, next) {
    console.log('Login was called in the Sample');
    res.redirect('/');
});

// POST /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   home page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
server.get('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  function(req, res, next) { 
    console.log("the king has returned");
    res.redirect('/');
    res.end();
    next();
  });

server.get('/logout', function(req, res, next){
  req.logout();
  res.redirect('/');
});

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(id, done) {
  done(null, id);
});

// Use the v2 endpoint (applications configured by apps.dev.microsoft.com)
// For passport-azure-ad v2.0.0, had to set realm = 'common' to ensure works on azure app service
var realm = AZUREAD_APP_REALM; 
let oidStrategyv2 = {
  redirectUrl: callbackURI,
  realm: realm,
  clientID: AZUREAD_APP_ID,
  clientSecret: AZUREAD_APP_PASSWORD,
  identityMetadata: 'https://login.microsoftonline.com/' + realm + '/v2.0/.well-known/openid-configuration',
  skipUserProfile: false,
  validateIssuer: false,
  allowHttpForRedirectUrl: true,
  responseType: 'code',
  responseMode: 'query',
  scope:['email', 'profile', 'offline_access', 'https://outlook.office.com/mail.read'],
  passReqToCallback: false
};

// Use the v1 endpoint (applications configured by manage.windowsazure.com)
// This works against Azure AD
let oidStrategyv1 = {
  redirectUrl: callbackURI,
  realm: realm,
  clientID: AZUREAD_APP_ID,
  clientSecret: AZUREAD_APP_PASSWORD,
  validateIssuer: false,
  //allowHttpForRedirectUrl: true,
  oidcIssuer: undefined,
  identityMetadata: 'https://login.microsoftonline.com/' + realm + '/.well-known/openid-configuration',
  skipUserProfile: true,
  responseType: 'code',
  responseMode: 'query',
  passReqToCallback: true
};

let strategy = null;
if ( AUTH_STRATEGY == 'oidStrategyv1') {
  strategy = oidStrategyv1;
}
if ( AUTH_STRATEGY == 'oidStrategyv2') {
  strategy = oidStrategyv2;
}

var users = [];

var findByOid = function(oid, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
   console.log('we are using user: ', user);
    if (user.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

passport.use(new OIDCStrategy(strategy,
  function(iss, sub, profile, accessToken, refreshToken, done) {
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByOid(profile.oid, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      });
    });
  }
));

function getAccessTokenWithRefreshToken(refreshToken, callback){
  console.log("getAccessTokenWithRefreshToken");
  var data = 'grant_type=refresh_token' 
        + '&refresh_token=' + refreshToken
        + '&client_id=' + AZUREAD_APP_ID
        + '&client_secret=' + encodeURIComponent(AZUREAD_APP_PASSWORD) 

  var options = {
      method: 'POST',
      url: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      body: data,
      json: true,
      headers: { 'Content-Type' : 'application/x-www-form-urlencoded' }
  };

  request(options, function (err, res, body) {
      if (err) return callback(err, body, res);
      if (parseInt(res.statusCode / 100, 10) !== 2) {
          if (body.error) {
              return callback(new Error(res.statusCode + ': ' + (body.error.message || body.error)), body, res);
          }
          if (!body.access_token) {
              return callback(new Error(res.statusCode + ': refreshToken error'), body, res);
          }
          return callback(null, body, res);
      }
      callback(null, {
          accessToken: body.access_token,
          refreshToken: body.refresh_token
      }, res);
  }); 
}

