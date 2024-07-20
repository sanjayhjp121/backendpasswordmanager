const express = require('express')
const router = express.Router()
require('../config/passport')
const passport = require('passport')
const requireAuth = passport.authenticate('jwt', {
    session: false
})
const controller = require('../controllers/admin');
const trimRequest = require('trim-request')
const authorize = require('../middlewares/authorize')



router.post(
    '/addAdmin',
    controller.addAdmin
)


router.post(
    '/login',
    trimRequest.all,
    controller.login
)

router.get(
    '/getUserList',
    trimRequest.all,
    requireAuth,
    authorize('superadmin'),
    controller.getUserList
)

router.get(
    '/getUserDetail',
    trimRequest.all,
    requireAuth,
    authorize('superadmin'),
    controller.getUserDetail
)


module.exports = router