require('../config/passport')
const express = require('express');
const router = express.Router()
const controller = require('../controllers/user');
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
    '/signup',
    controller.signup
)


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
    authorize('user'),
    controller.getProfile
)


router.post(
    '/createPassword',
    requireAuth,
    authorize('user'),
    controller.createPassword
)

router.post(
    '/createMember',
    requireAuth,
    authorize('user'),
    controller.createMember
)

router.get(
    '/listAllMember',
    requireAuth,
    authorize('user'),
    controller.listAllMember
)

router.post(
    '/grantAccess',
    requireAuth,
    authorize('user'),
    controller.grantAccess
)

router.post(
    '/revokeAccess',
    requireAuth,
    authorize('user'),
    controller.revokeAccess
)

router.post(
    '/revealPassword',
    requireAuth,
    authorize('user'),
    controller.revealPassword
)

router.post(
    '/createAgency',
    requireAuth,
    authorize('user'),
    controller.createAgency
)

router.get(
    '/listAllPasswordByAgency',
    requireAuth,
    authorize('user'),
    controller.listAllPasswordByAgency
)

router.get(
    '/listAllAgency',
    requireAuth,
    authorize('user'),
    controller.listAllAgency
)

=======
require('../config/passport')
const express = require('express');
const router = express.Router()
const controller = require('../controllers/user');
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
    '/signup',
    controller.signup
)


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
    authorize('user'),
    controller.getProfile
)


router.post(
    '/createPassword',
    requireAuth,
    authorize('user'),
    controller.createPassword
)

router.post(
    '/createMember',
    requireAuth,
    authorize('user'),
    controller.createMember
)

router.get(
    '/listAllMember',
    requireAuth,
    authorize('user'),
    controller.listAllMember
)

router.post(
    '/grantAccess',
    requireAuth,
    authorize('user'),
    controller.grantAccess
)

router.post(
    '/revokeAccess',
    requireAuth,
    authorize('user'),
    controller.revokeAccess
)

router.post(
    '/revealPassword',
    requireAuth,
    authorize('user'),
    controller.revealPassword
)

router.post(
    '/createAgency',
    requireAuth,
    authorize('user'),
    controller.createAgency
)

router.get(
    '/listAllPasswordByAgency',
    requireAuth,
    authorize('user'),
    controller.listAllPasswordByAgency
)

router.get(
    '/listAllAgency',
    requireAuth,
    authorize('user'),
    controller.listAllAgency
)

module.exports = router