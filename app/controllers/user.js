const path = require('path')
const {
    uploadFileToLocal
} = require("../utils/helpers");

const absolutePath = path.join(__dirname, '../../public/');

const utils = require('../utils/utils')
// const UserAccess = require('../../models/userAccess')
const emailer = require('../utils/emailer')
const jwt = require("jsonwebtoken")
const { getMessage } = require("../utils/responseMessage")
const { default: mongoose } = require('mongoose');
const useragent = require('useragent');
const expressIp = require('express-ip');
const geoip = require('geoip-lite');


const memberModel = require('../models/member')
const passwordModel = require('../models/password');
const OTP = require('../models/otp')
const User = require('../models/user')
const Log = require('../models/logs');
const subscription = require('../models/subscription');
const agency = require('../models/agency');
// ------------------------------------------------------------------------


exports.test = async (req, res) => {
    try {
        console.log("user test routes")
        res.send("User Routes test")
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" })
    }
}



// -------------------------------- LOGIN & SIGNUP ---------------------
const generateToken = (_id) => {
    const expiration = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * process.env.JWT_EXPIRATION_DAY)
    return utils.encrypt(
        jwt.sign(
            {
                data: {
                    _id,
                    type: "user"
                },
                // exp: expiration
            },
            process.env.JWT_SECRET
        )
    )
}

const registerUser = async data => {
    return new Promise(async (resolve, reject) => {
        try {
            const user = new User(data)
            await user.save()
            resolve(user)
        } catch (error) {
            reject(error)
        }
    })
}


/**
 * Saves a new user access and then returns token
 * @param {Object} req - request object
 * @param {Object} user - user object
 */

const saveUserAccessAndReturnToken = async (req, user) => {
    return new Promise(async (resolve, reject) => {

        try {
            resolve(generateToken(user._id))
        } catch (error) {
            reject(error)
        }

    })
}

exports.checkPhoneNumberExist = async (req, res) => {
    try {
        const { phone_number } = req.body;
        const doesPhoneNumberExist = await emailer.checkMobileExists(phone_number);
        res.json({ data: doesPhoneNumberExist, code: 200 })
    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.checkEmailExist = async (req, res) => {
    try {
        const { email } = req.body;
        const doesEmailExists = await emailer.emailExists(email);
        res.json({ data: doesEmailExists, code: 200 })
    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.login = async (req, res) => {
    try {
        const data = req.body;
        let user = await User.findOne({ $or: [{ email: data.email }, { username: data.email }] }, "+password");

        if (!user) return utils.handleError(res, { message: "Invalid login credentials. Please try again", code: 400 });

        if (user.status !== "active") return utils.handleError(res, { message: "Your account has been deactivated", code: 400 });
        // if (user.is_deleted === true) return utils.handleError(res, { message: "Your account has been deleted", code: 400 });

        const isPasswordMatch = await utils.checkPassword(data.password, user);
        if (!isPasswordMatch) return utils.handleError(res, { message: "Invalid login credentials. Please try again", code: 400 });

        const token = await saveUserAccessAndReturnToken(req, user)
        user = user.toJSON()
        delete user.password
        res.status(200).json({ code: 200, data: { user: user, token: token } });
    } catch (error) {
        utils.handleError(res, error);
    }
};


async function checkPhoneNumberVerified(phone_number) {
    try {
        const otpData = await OTP.findOne({ phone_number });
        if (!otpData || otpData.verified !== true) return false
        return true
    } catch (error) {
        console.log(error)
        return false
    }
}


exports.signup = async (req, res) => {
    try {
        const data = req.body;

        const doesEmailExists = await emailer.emailExists(data.email);
        if (doesEmailExists) return res.status(400).json({ message: "This email address is already registered", code: 400 });

        const doesPhoneNumberExist = await emailer.checkMobileExists(data.phone_number);
        if (doesPhoneNumberExist) return res.status(400).json({ message: "This phone number is already registered", code: 400 });

        // const isPhoneNumberVerified = await checkPhoneNumberVerified(data.phone_number);
        // if (!isPhoneNumberVerified) return res.status(400).json({ message: "Your phone number has not been verified. Please verify your phone number to continue", code: 400 });
        // if (data.backup_email && data.backup_email === data.email) return res.status(400).json({ message: "Backup email address cannot be the same as the primary email address. Please enter a different email", code: 400 });

        let user = await registerUser(data);
        const token = await saveUserAccessAndReturnToken(req, user)

        user = user.toJSON()
        delete user.password

        res.status(200).json({ code: 200, data: { user: user, token: token } });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" });
    }
};



exports.sendOTP = async (req, res) => {
    try {
        const { phone_number } = req.body;
        const otpData = await OTP.findOne({ phone_number });

        console.log("Phone number : " + phone_number)

        const otp = utils.generateOTP();

        const data = {
            phone_number: phone_number,
            otp,
            exp_time: new Date(Date.now() + (1000 * 60 * 10)),
            is_used: false
        }

        if (otpData) {
            await OTP.findByIdAndUpdate(otpData._id, data)
        } else {
            const saveOTP = new OTP(data);
            await saveOTP.save()
        }
        res.json({ code: 200, message: "OTP has been sent successfully", otp: data.otp })
    } catch (error) {
        utils.handleError(res, error);
    }
}

exports.sendOTPToEmail = async (req, res) => {
    try {
        const { email } = req.body;
        const otpData = await OTP.findOne({ email });

        console.log("Email : " + email)

        const otp = utils.generateOTP();

        const data = {
            email,
            otp,
            exp_time: new Date(Date.now() + (1000 * 60 * 10)),
            is_used: false
        }

        if (otpData) {
            await OTP.findByIdAndUpdate(otpData._id, data)
        } else {
            const saveOTP = new OTP(data);
            await saveOTP.save()
        }

        const mailOptions = {
            to: email,
            subject: "Your OTP",
            otp: otp,
            name: "User"
        }
        emailer.sendEmail(null, mailOptions, "otpVerification");


        res.json({ code: 200, message: "OTP has been sent successfully to register email", otp: data.otp })
    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.verifyOTP = async (req, res) => {
    try {
        const { otp, phone_number, email } = req.body;

        const condition = {
            otp
        }

        if (phone_number) {
            condition.phone_number = phone_number
        }
        else if (email) {
            condition.email = email
        }

        const otpData = await OTP.findOne(condition);

        if (!otpData || otpData.otp !== otp) {
            return res.status(500).json({ message: "The OTP you entered is incorrect. Please try again", code: 400 });
        }

        if (otpData.is_used) {
            return res.status(500).json({ message: "This OTP has already been used. Please request a new one", code: 400 });
        }
        if (otpData.exp_time < new Date()) {
            return res.status(500).json({ message: "The OTP you entered has expired. Please request a new one", code: 400 });
        }

        otpData.verified = true;
        otpData.is_used = true;
        await otpData.save();

        return res.json({ code: 200, message: "OTP verified successfully" })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Internal server error" })
    }
}

exports.forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email: email })
        if (!user) return utils.handleError(res, { message: "No account found with the provided information", code: 400 });


        const mailOptions = {
            to: user.email,
            subject: "Your OTP for Password Reset",
            reset_link: `${process.env.BASE_URL}views/passwordReset.ejs?user_id=${user._id}`,
            name: user.full_name
        }
        emailer.sendEmail(null, mailOptions, "forgotPasswordWithLink");

        return res.json({ code: 200, message: "E-mail sent successfully" })

    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.resetPassword = async (req, res) => {
    try {

        const { user_id, password } = req.body;
        const user = await User.findOne({ _id: new mongoose.Types.ObjectId(user_id) });

        console.log("user", user)

        user.password = password;
        await user.save()

        res.json({ message: "Your password has been reset successfully", code: 200 })
    } catch (error) {
        utils.handleError(res, error);
    }
}

exports.changePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user_id = req.user._id

        let user = await User.findById(user_id, "+password");
        const isPasswordMatch = await utils.checkPassword(currentPassword, user);
        if (!isPasswordMatch) return utils.handleError(res, { message: "Current password is incorrect", code: 400 });

        const newPasswordMatch = await utils.checkPassword(newPassword, user);
        if (newPasswordMatch) return utils.handleError(res, { message: "New password must be different from the current password", code: 400 });

        user.password = newPassword;

        await user.save();

        res.status(200).json({ message: 'Password has been changed successfully' });
    } catch (error) {
        utils.handleError(res, error);
    }
};



// ---------------------------------------------------------------------

exports.uploadFileToServer = async (req, res) => {
    try {
        var file = await uploadFileToLocal({
            image_data: req.files.media,
            path: `${process.env.STORAGE_PATH}${req.body.path}`,
        });

        const path = `${process.env.STORAGE_PATH_HTTP}${req.body.path}/${file}`


        res.json({
            code: 200,
            path: path,
        });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error" })
    }
}



exports.getProfile = async (req, res) => {
    try {
        const data = await User.findOne({ _id: new mongoose.Types.ObjectId(req.user._id) });

        return res.status(200).json({ data: data });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

exports.createAgency = async (req, res) => {
    try {
        const data = req.body;
        data.user = req.user._id
        const agencyData = new agency(data);
        await agencyData.save();
        return res.status(200).json({ message: "Agency saved successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

exports.listAllAgency = async (req, res) => {
    try {
        const data = await agency.find({ user: new mongoose.Types.ObjectId(req.user._id) })
        return res.status(200).json({ data: data });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

exports.createPassword = async (req, res) => {
    try {
        const { siteName, siteURL, username, password, agencyId } = req.body;
        const user = req.user;
        const passwordCount = await passwordModel.countDocuments({ user: user._id });

        let limit;
        switch (user.plan) {
            case 'basic':
                limit = 5;
                break;
            case 'mini':
                limit = 50;
                break;
            case 'agency':
                limit = Infinity;
                break;
            default:
                limit = 0;
        }

        if (passwordCount >= limit) {
            return res.status(403).json({ msg: 'Password limit reached' });
        }

        const newPassword = new passwordModel({ user: user._id, siteName, siteURL, username, password,agency: agencyId });
        await newPassword.save();
        return res.status(201).json({ message: 'Password saved successfully' });
    } catch (error) {
        console.log(error);
        return res.status(500).json("Internal server error");
    }
}



exports.createMember = async (req, res) => {
    try {
        const data = req.body;
        data.user = req.user._id;
        // data.agency = data.agencyId
        if (typeof data.agencyId === 'string') {
            data.agency = new mongoose.Types.ObjectId(data.agencyId);
        } else {
            data.agency = data.agencyId;
        }

        if (!data.password) {
            data.password = generateRandomPassword();
        }

        if (!data.username) {
            data.username = await generateUsername(data.full_name);
        }

        const newMember = new memberModel(data);
        await newMember.save();
        return res.status(201).json({ message: 'Member saved successfully' });
    } catch (error) {
        console.log(error);
        return res.status(500).json("Internal server error");
    }
};

const generateRandomPassword = () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    for (let i = 0; i < 8; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
};

const generateUsername = async (fullName) => {
    const baseUsername = fullName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10);
    let uniqueUsername = baseUsername;
    let exists = true;
    let counter = 1;

    while (exists) {
        exists = await mongoose.models.members.findOne({ username: uniqueUsername });
        if (exists) {
            uniqueUsername = baseUsername + counter;
            counter++;
        }
    }
    return uniqueUsername;
};



exports.grantAccess = async (req, res) => {
    try {
        const { passwordId, memberId } = req.body;
        const password = await passwordModel.findById(passwordId);

        if (!password) {
            return res.status(404).json({ message: 'Password not found' });
        }

        if (!password.user.equals(req.user._id)) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        if (!password.access.includes(memberId)) {
            password.access.push(memberId);
            await password.save();
        }

        return res.status(200).json({ message: 'Access granted successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};


exports.revokeAccess = async (req, res) => {
    try {
        const { passwordId, memberId } = req.body;
        const password = await passwordModel.findById(passwordId);

        if (!password) {
            return res.status(404).json({ message: 'Password not found' });
        }

        if (!password.user.equals(req.user._id)) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        password.access = password.access.filter(id => !id.equals(memberId));
        await password.save();

        return res.status(200).json({ message: 'Access revoked successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};


exports.listAllMember = async (req, res) => {
    try {
        const memberlist = await memberModel.find({ agency: new mongoose.Types.ObjectId(req.query.agencyid) });
        return res.status(200).json({ data: memberlist });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}



exports.revealPassword = async (req, res) => {
    try {
        const { id, username } = req.body;
        // const credential = await Credential.findById(id);

        // if (!credential) return res.status(404).json({ message: 'Credential not found' });

        // const isPasswordCorrect = await bcrypt.compare(req.body.password, credential.password);
        const isPasswordCorrect = true

        if (isPasswordCorrect) {
            const agent = useragent.parse(req.headers['user-agent']);
            const geo = geoip.lookup(req.ipInfo.ip);

            const logEntry = new Log({
                action: 'reveal',
                user: { id: req.user.id, username: req.user.unique_id },
                ip: req.ipInfo.ip,
                browser: agent.toAgent(),
                os: agent.os.toString(),
                location: {
                    country: geo ? geo.country : 'Unknown',
                    region: geo ? geo.region : 'Unknown',
                    city: geo ? geo.city : 'Unknown'
                },
                device: agent.device.toString(),
                network: req.headers['network-type'] || 'Unknown',
                requestUrl: req.originalUrl,
                requestMethod: req.method,
                responseStatus: 200,
                responseTime: Date.now() - req.startTime, // assuming req.startTime is set at request start
                // metadata: { website: credential.website }
            });

            await logEntry.save();

            res.json({ password: req.body.password });
        } else {
            res.status(401).json({ message: 'Incorrect password' });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}



exports.createSubscription = async (req, res) => {
    try {
        const data = req.body;
        if (!data.expiration_date) {
            return res.status(422).json({ message: 'Expiration date is required' })
        }
        const subscriptionData = new subscription(data);
        await subscriptionData.save();
        return res.status(200).json({ message: "Subscription saved successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}


exports.createVault = async (req, res) => {
    try {
        const data = req.body;
        if (!data.expiration_date) {
            return res.status(422).json({ message: 'Expiration date is required' })
        }
        const subscriptionData = new subscription(data);
        await subscriptionData.save();
        return res.status(200).json({ message: "Subscription saved successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}



exports.listAllPasswordByAgency = async (req, res) => {
    try {
        const passwordlist = await passwordModel.find({ agency: new mongoose.Types.ObjectId(req.query.agencyid) });
        return res.status(200).json({ data: passwordlist });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
const path = require('path')
const {
    uploadFileToLocal
} = require("../utils/helpers");

const absolutePath = path.join(__dirname, '../../public/');

const utils = require('../utils/utils')
// const UserAccess = require('../../models/userAccess')
const emailer = require('../utils/emailer')
const jwt = require("jsonwebtoken")
const { getMessage } = require("../utils/responseMessage")
const { default: mongoose } = require('mongoose');
const useragent = require('useragent');
const expressIp = require('express-ip');
const geoip = require('geoip-lite');


const memberModel = require('../models/member')
const passwordModel = require('../models/password');
const OTP = require('../models/otp')
const User = require('../models/user')
const Log = require('../models/logs');
const subscription = require('../models/subscription');
const agency = require('../models/agency');
// ------------------------------------------------------------------------


exports.test = async (req, res) => {
    try {
        console.log("user test routes")
        res.send("User Routes test")
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" })
    }
}



// -------------------------------- LOGIN & SIGNUP ---------------------
const generateToken = (_id) => {
    const expiration = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * process.env.JWT_EXPIRATION_DAY)
    return utils.encrypt(
        jwt.sign(
            {
                data: {
                    _id,
                    type: "user"
                },
                // exp: expiration
            },
            process.env.JWT_SECRET
        )
    )
}

const registerUser = async data => {
    return new Promise(async (resolve, reject) => {
        try {
            const user = new User(data)
            await user.save()
            resolve(user)
        } catch (error) {
            reject(error)
        }
    })
}


/**
 * Saves a new user access and then returns token
 * @param {Object} req - request object
 * @param {Object} user - user object
 */

const saveUserAccessAndReturnToken = async (req, user) => {
    return new Promise(async (resolve, reject) => {

        try {
            resolve(generateToken(user._id))
        } catch (error) {
            reject(error)
        }

    })
}

exports.checkPhoneNumberExist = async (req, res) => {
    try {
        const { phone_number } = req.body;
        const doesPhoneNumberExist = await emailer.checkMobileExists(phone_number);
        res.json({ data: doesPhoneNumberExist, code: 200 })
    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.checkEmailExist = async (req, res) => {
    try {
        const { email } = req.body;
        const doesEmailExists = await emailer.emailExists(email);
        res.json({ data: doesEmailExists, code: 200 })
    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.login = async (req, res) => {
    try {
        const data = req.body;
        let user = await User.findOne({ $or: [{ email: data.email }, { username: data.email }] }, "+password");

        if (!user) return utils.handleError(res, { message: "Invalid login credentials. Please try again", code: 400 });

        if (user.status !== "active") return utils.handleError(res, { message: "Your account has been deactivated", code: 400 });
        // if (user.is_deleted === true) return utils.handleError(res, { message: "Your account has been deleted", code: 400 });

        const isPasswordMatch = await utils.checkPassword(data.password, user);
        if (!isPasswordMatch) return utils.handleError(res, { message: "Invalid login credentials. Please try again", code: 400 });

        const token = await saveUserAccessAndReturnToken(req, user)
        user = user.toJSON()
        delete user.password
        res.status(200).json({ code: 200, data: { user: user, token: token } });
    } catch (error) {
        utils.handleError(res, error);
    }
};


async function checkPhoneNumberVerified(phone_number) {
    try {
        const otpData = await OTP.findOne({ phone_number });
        if (!otpData || otpData.verified !== true) return false
        return true
    } catch (error) {
        console.log(error)
        return false
    }
}


exports.signup = async (req, res) => {
    try {
        const data = req.body;

        const doesEmailExists = await emailer.emailExists(data.email);
        if (doesEmailExists) return res.status(400).json({ message: "This email address is already registered", code: 400 });

        const doesPhoneNumberExist = await emailer.checkMobileExists(data.phone_number);
        if (doesPhoneNumberExist) return res.status(400).json({ message: "This phone number is already registered", code: 400 });

        // const isPhoneNumberVerified = await checkPhoneNumberVerified(data.phone_number);
        // if (!isPhoneNumberVerified) return res.status(400).json({ message: "Your phone number has not been verified. Please verify your phone number to continue", code: 400 });
        // if (data.backup_email && data.backup_email === data.email) return res.status(400).json({ message: "Backup email address cannot be the same as the primary email address. Please enter a different email", code: 400 });

        let user = await registerUser(data);
        const token = await saveUserAccessAndReturnToken(req, user)

        user = user.toJSON()
        delete user.password

        res.status(200).json({ code: 200, data: { user: user, token: token } });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" });
    }
};



exports.sendOTP = async (req, res) => {
    try {
        const { phone_number } = req.body;
        const otpData = await OTP.findOne({ phone_number });

        console.log("Phone number : " + phone_number)

        const otp = utils.generateOTP();

        const data = {
            phone_number: phone_number,
            otp,
            exp_time: new Date(Date.now() + (1000 * 60 * 10)),
            is_used: false
        }

        if (otpData) {
            await OTP.findByIdAndUpdate(otpData._id, data)
        } else {
            const saveOTP = new OTP(data);
            await saveOTP.save()
        }
        res.json({ code: 200, message: "OTP has been sent successfully", otp: data.otp })
    } catch (error) {
        utils.handleError(res, error);
    }
}

exports.sendOTPToEmail = async (req, res) => {
    try {
        const { email } = req.body;
        const otpData = await OTP.findOne({ email });

        console.log("Email : " + email)

        const otp = utils.generateOTP();

        const data = {
            email,
            otp,
            exp_time: new Date(Date.now() + (1000 * 60 * 10)),
            is_used: false
        }

        if (otpData) {
            await OTP.findByIdAndUpdate(otpData._id, data)
        } else {
            const saveOTP = new OTP(data);
            await saveOTP.save()
        }

        const mailOptions = {
            to: email,
            subject: "Your OTP",
            otp: otp,
            name: "User"
        }
        emailer.sendEmail(null, mailOptions, "otpVerification");


        res.json({ code: 200, message: "OTP has been sent successfully to register email", otp: data.otp })
    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.verifyOTP = async (req, res) => {
    try {
        const { otp, phone_number, email } = req.body;

        const condition = {
            otp
        }

        if (phone_number) {
            condition.phone_number = phone_number
        }
        else if (email) {
            condition.email = email
        }

        const otpData = await OTP.findOne(condition);

        if (!otpData || otpData.otp !== otp) {
            return res.status(500).json({ message: "The OTP you entered is incorrect. Please try again", code: 400 });
        }

        if (otpData.is_used) {
            return res.status(500).json({ message: "This OTP has already been used. Please request a new one", code: 400 });
        }
        if (otpData.exp_time < new Date()) {
            return res.status(500).json({ message: "The OTP you entered has expired. Please request a new one", code: 400 });
        }

        otpData.verified = true;
        otpData.is_used = true;
        await otpData.save();

        return res.json({ code: 200, message: "OTP verified successfully" })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Internal server error" })
    }
}

exports.forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email: email })
        if (!user) return utils.handleError(res, { message: "No account found with the provided information", code: 400 });


        const mailOptions = {
            to: user.email,
            subject: "Your OTP for Password Reset",
            reset_link: `${process.env.BASE_URL}views/passwordReset.ejs?user_id=${user._id}`,
            name: user.full_name
        }
        emailer.sendEmail(null, mailOptions, "forgotPasswordWithLink");

        return res.json({ code: 200, message: "E-mail sent successfully" })

    } catch (error) {
        utils.handleError(res, error);
    }
}


exports.resetPassword = async (req, res) => {
    try {

        const { user_id, password } = req.body;
        const user = await User.findOne({ _id: new mongoose.Types.ObjectId(user_id) });

        console.log("user", user)

        user.password = password;
        await user.save()

        res.json({ message: "Your password has been reset successfully", code: 200 })
    } catch (error) {
        utils.handleError(res, error);
    }
}

exports.changePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user_id = req.user._id

        let user = await User.findById(user_id, "+password");
        const isPasswordMatch = await utils.checkPassword(currentPassword, user);
        if (!isPasswordMatch) return utils.handleError(res, { message: "Current password is incorrect", code: 400 });

        const newPasswordMatch = await utils.checkPassword(newPassword, user);
        if (newPasswordMatch) return utils.handleError(res, { message: "New password must be different from the current password", code: 400 });

        user.password = newPassword;

        await user.save();

        res.status(200).json({ message: 'Password has been changed successfully' });
    } catch (error) {
        utils.handleError(res, error);
    }
};



// ---------------------------------------------------------------------

exports.uploadFileToServer = async (req, res) => {
    try {
        var file = await uploadFileToLocal({
            image_data: req.files.media,
            path: `${process.env.STORAGE_PATH}${req.body.path}`,
        });

        const path = `${process.env.STORAGE_PATH_HTTP}${req.body.path}/${file}`


        res.json({
            code: 200,
            path: path,
        });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error" })
    }
}



exports.getProfile = async (req, res) => {
    try {
        const data = await User.findOne({ _id: new mongoose.Types.ObjectId(req.user._id) });

        return res.status(200).json({ data: data });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

exports.createAgency = async (req, res) => {
    try {
        const data = req.body;
        data.user = req.user._id
        const agencyData = new agency(data);
        await agencyData.save();
        return res.status(200).json({ message: "Agency saved successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

exports.listAllAgency = async (req, res) => {
    try {
        const data = await agency.find({ user: new mongoose.Types.ObjectId(req.user._id) })
        return res.status(200).json({ data: data });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

exports.createPassword = async (req, res) => {
    try {
        const { siteName, siteURL, username, password, agencyId } = req.body;
        const user = req.user;
        const passwordCount = await passwordModel.countDocuments({ user: user._id });

        let limit;
        switch (user.plan) {
            case 'basic':
                limit = 5;
                break;
            case 'mini':
                limit = 50;
                break;
            case 'agency':
                limit = Infinity;
                break;
            default:
                limit = 0;
        }

        if (passwordCount >= limit) {
            return res.status(403).json({ msg: 'Password limit reached' });
        }

        const newPassword = new passwordModel({ user: user._id, siteName, siteURL, username, password,agency: agencyId });
        await newPassword.save();
        return res.status(201).json({ message: 'Password saved successfully' });
    } catch (error) {
        console.log(error);
        return res.status(500).json("Internal server error");
    }
}



exports.createMember = async (req, res) => {
    try {
        const data = req.body;
        data.user = req.user._id;
        // data.agency = data.agencyId
        if (typeof data.agencyId === 'string') {
            data.agency = new mongoose.Types.ObjectId(data.agencyId);
        } else {
            data.agency = data.agencyId;
        }

        if (!data.password) {
            data.password = generateRandomPassword();
        }

        if (!data.username) {
            data.username = await generateUsername(data.full_name);
        }

        const newMember = new memberModel(data);
        await newMember.save();
        return res.status(201).json({ message: 'Member saved successfully' });
    } catch (error) {
        console.log(error);
        return res.status(500).json("Internal server error");
    }
};

const generateRandomPassword = () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    for (let i = 0; i < 8; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
};

const generateUsername = async (fullName) => {
    const baseUsername = fullName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10);
    let uniqueUsername = baseUsername;
    let exists = true;
    let counter = 1;

    while (exists) {
        exists = await mongoose.models.members.findOne({ username: uniqueUsername });
        if (exists) {
            uniqueUsername = baseUsername + counter;
            counter++;
        }
    }
    return uniqueUsername;
};



exports.grantAccess = async (req, res) => {
    try {
        const { passwordId, memberId } = req.body;
        const password = await passwordModel.findById(passwordId);

        if (!password) {
            return res.status(404).json({ message: 'Password not found' });
        }

        if (!password.user.equals(req.user._id)) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        if (!password.access.includes(memberId)) {
            password.access.push(memberId);
            await password.save();
        }

        return res.status(200).json({ message: 'Access granted successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};


exports.revokeAccess = async (req, res) => {
    try {
        const { passwordId, memberId } = req.body;
        const password = await passwordModel.findById(passwordId);

        if (!password) {
            return res.status(404).json({ message: 'Password not found' });
        }

        if (!password.user.equals(req.user._id)) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        password.access = password.access.filter(id => !id.equals(memberId));
        await password.save();

        return res.status(200).json({ message: 'Access revoked successfully' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};


exports.listAllMember = async (req, res) => {
    try {
        const memberlist = await memberModel.find({ agency: new mongoose.Types.ObjectId(req.query.agencyid) });
        return res.status(200).json({ data: memberlist });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}



exports.revealPassword = async (req, res) => {
    try {
        const { id, username } = req.body;
        // const credential = await Credential.findById(id);

        // if (!credential) return res.status(404).json({ message: 'Credential not found' });

        // const isPasswordCorrect = await bcrypt.compare(req.body.password, credential.password);
        const isPasswordCorrect = true

        if (isPasswordCorrect) {
            const agent = useragent.parse(req.headers['user-agent']);
            const geo = geoip.lookup(req.ipInfo.ip);

            const logEntry = new Log({
                action: 'reveal',
                user: { id: req.user.id, username: req.user.unique_id },
                ip: req.ipInfo.ip,
                browser: agent.toAgent(),
                os: agent.os.toString(),
                location: {
                    country: geo ? geo.country : 'Unknown',
                    region: geo ? geo.region : 'Unknown',
                    city: geo ? geo.city : 'Unknown'
                },
                device: agent.device.toString(),
                network: req.headers['network-type'] || 'Unknown',
                requestUrl: req.originalUrl,
                requestMethod: req.method,
                responseStatus: 200,
                responseTime: Date.now() - req.startTime, // assuming req.startTime is set at request start
                // metadata: { website: credential.website }
            });

            await logEntry.save();

            res.json({ password: req.body.password });
        } else {
            res.status(401).json({ message: 'Incorrect password' });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}



exports.createSubscription = async (req, res) => {
    try {
        const data = req.body;
        if (!data.expiration_date) {
            return res.status(422).json({ message: 'Expiration date is required' })
        }
        const subscriptionData = new subscription(data);
        await subscriptionData.save();
        return res.status(200).json({ message: "Subscription saved successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}


exports.createVault = async (req, res) => {
    try {
        const data = req.body;
        if (!data.expiration_date) {
            return res.status(422).json({ message: 'Expiration date is required' })
        }
        const subscriptionData = new subscription(data);
        await subscriptionData.save();
        return res.status(200).json({ message: "Subscription saved successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}



exports.listAllPasswordByAgency = async (req, res) => {
    try {
        const passwordlist = await passwordModel.find({ agency: new mongoose.Types.ObjectId(req.query.agencyid) });
        return res.status(200).json({ data: passwordlist });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
}