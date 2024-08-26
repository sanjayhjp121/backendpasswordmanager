const passport = require('passport')
const User = require('../models/user')
const Admin = require('../models/admin')
const Member = require('../models/member')
const JwtStrategy = require('passport-jwt').Strategy
const utils = require('../utils/utils')

/**
 * Extracts token from: header, body or query
 * @param {Object} req - request object
 * @returns {string} token - decrypted token
 */

const jwtExtractor = req => {
  let token = null
  if (req.headers.authorization) {
    token = req.headers.authorization.replace('Bearer ', '').trim()
  } else if (req.body.token) {
    token = req.body.token.trim()
  } else if (req.query.token) {
    token = req.query.token.trim()
  }
  if (token) {
    token = utils.decrypt(token)
  }
  return token
}

/**
 * Options object for jwt middlware
 */

const jwtOptions = {
  jwtFromRequest: jwtExtractor,
  secretOrKey: process.env.JWT_SECRET
}

/**
 * Login with JWT middleware
 */
// const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {

//   let collection = payload.data.type == "superadmin" ? Admin : User
//   collection.findOne({
//     _id: payload.data._id
//   }).then(user => {
//     return !user ? done(null, false) : done(null, user)
//   }).catch(err => {
//     console.log("err", err)
//     return done(err, false)
//   })
// })

const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  let collection;
  switch (payload.data.type) {
    case 'superadmin':
      collection = Admin;
      break;
    case 'user':
      collection = User;
      break;
    case 'member':
      collection = Member;
      break;
    default:
      return done(new Error('Invalid user type in JWT payload'), false);
  }

  collection.findOne({ _id: payload.data._id })
    .then(user => {
      if (!user) {
        return done(null, false);
      }
      return done(null, user);
    })
    .catch(err => {
      console.error('Error finding user:', err);
      return done(err, false);
    });
});

passport.use(jwtLogin)