require('../config/passport')
const express = require('express');
const router = express.Router()
const controller = require('../controllers/member');
const passport = require('passport')
const requireAuth = passport.authenticate('jwt', {
    session: false
})
const trimRequest = require('trim-request')
const authorize = require('../middlewares/authorize');



router.get(
    '/test',
    controller.test
)
// -----------------------------------------


router.post(
    '/login',
    trimRequest.all,
    controller.login
)

router.post(
    '/sendOTP',
    controller.sendOTP
)

router.post(
    '/sendOTPToEmail',
    controller.sendOTPToEmail
)

router.post(
    '/verifyOTP',
    controller.verifyOTP
)

router.post(
    '/forgetPassword',
    controller.forgetPassword
)


router.post(
    '/resetPassword',
    controller.resetPassword
)

// ------------------------------------------------

router.post(
    '/uploadFileToServer',
    controller.uploadFileToServer
)


router.get(
    '/getProfile',
    requireAuth,
    authorize('member'),
    controller.getProfile
)

router.get(
    '/getGrantedPasswordList',
    requireAuth,
    authorize('member'),
    controller.getGrantedPasswordList
)


module.exports = router