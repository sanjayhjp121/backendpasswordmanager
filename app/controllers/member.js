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


const memberModel = require('../models/member')
const passwordModel = require('../models/password');
const OTP = require('../models/otp')

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
                    type: "member"
                },
                // exp: expiration
            },
            process.env.JWT_SECRET
        )
    )
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

exports.login = async (req, res) => {
    try {
        const data = req.body;
        let user = await memberModel.findOne({ $or: [{ email: data.email }, { username: data.email }] }, "+password");

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
        console.log("user id : " + req.user._id)
        const data = await memberModel.findOne({ _id: new mongoose.Types.ObjectId(req.user._id) });

        return res.status(200).json({ data: data });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error" });
    }
}



// exports.getGrantedPasswordList = async (req, res) => {
//     try {
//         const userID = req.user._id;
//         const data = await passwordModel.find({
//             access: userID
//         }).populate('user', 'username');
//         const filteredPasswords = data.filter(password => {
//             const accessIds = password.access.map(access => access.toString());
//             return accessIds.includes(userID.toString());
//         });

//         res.status(200).json({ data: filteredPasswords });
//     } catch (error) {
//         console.error('Error fetching passwords:', error);
//         return res.status(500).json({ message: "Internal server error" });
//     }
// };



exports.getGrantedPasswordList = async (req, res) => {
    try {
        const userID = req.user._id;

        const data = await passwordModel.find({
            access: userID
        }).select('-user -access');

        res.status(200).json({ data });
    } catch (error) {
        console.error('Error fetching passwords:', error);
        return res.status(500).json({ message: "Internal server error" });
    }
};