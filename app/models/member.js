const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");
const validator = require("validator");
const mongoosePaginate = require("mongoose-paginate-v2");

const memberSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
        },
        agency: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'agency',
            required: true,
        },
        url: {
            type: String
        },
        full_name: {
            type: String,
            required: true,
        },
        username: {
            type: String,
            unique: true,
            required: true
        },
        password: {
            type: String,
            required: true,
            select: false
        },
        email: {
            type: String,
            validate: {
                validator: validator.isEmail,
                message: "EMAIL_IS_NOT_VALID",
            },
            unique: true,
            lowercase: true,
            required: true,
        },
        recovery_email: {
            type: String,
            validate: {
                validator: validator.isEmail,
                message: "EMAIL_IS_NOT_VALID",
            },
            lowercase: true,
        },
        phone_number: {
            type: String,
            unique: true,
        },
        dob:{
            type: String
        },
        email_verified: {
            type: Boolean,
            default: false
        },
        phone_number_verified: {
            type: Boolean,
            default: false
        },
        decoded_password: {
            type: String,
            select: false
        },
        role: {
            type: String,
            enum: ["member"],
            default: "member",
            required: true
        },
        status: {
            type: String,
            enum: ["active", "inactive"],
            default: "active"
        },
        recovery_code : {
            type: String
        },
        authQR : {
            type: String
        },
        auth_code: {
            type: String
        },
        screenshot: {
            type: String
        },
        notes: {
            type: String
        }
    },
    {
        timestamps: true,
    }
);

const hash = (user, salt, next) => {
    bcrypt.hash(user.password, salt, null, (error, newHash) => {
        if (error) {
            return next(error);
        }
        user.password = newHash;
        return next();
    });
};

const genSalt = (user, SALT_FACTOR, next) => {
    bcrypt.genSalt(SALT_FACTOR, (err, salt) => {
        if (err) {
            return next(err);
        }
        return hash(user, salt, next);
    });
};

const generateUniqueCode = async () => {
    let uniqueId;
    let exists = true;
    while (exists) {
        uniqueId = Math.floor(100000 + Math.random() * 900000);
        exists = await mongoose.models.members.findOne({ unique_id: uniqueId });
    }
    return uniqueId;
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

const generateRandomPassword = () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    for (let i = 0; i < 8; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
};

memberSchema.pre("save", async function (next) {
    const that = this;
    const SALT_FACTOR = 5;

    if (!this.unique_id) {
        this.unique_id = await generateUniqueCode();
    }

    if (!this.username) {
        this.username = await generateUsername(this.full_name);
    }

    if (!this.password) {
        this.password = generateRandomPassword();
    }

    this.decoded_password = this.password;

    if (!that.isModified("password")) {
        return next();
    }
    return genSalt(that, SALT_FACTOR, next);
});

memberSchema.methods.comparePassword = function (passwordAttempt, cb) {
    bcrypt.compare(passwordAttempt, this.password, (err, isMatch) =>
        err ? cb(err) : cb(null, isMatch)
    );
};

memberSchema.plugin(mongoosePaginate);

module.exports = mongoose.model("members", memberSchema);
