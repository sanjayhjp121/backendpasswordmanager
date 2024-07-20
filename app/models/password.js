const mongoose = require('mongoose');
const bcrypt = require("bcrypt-nodejs");
const validator = require("validator");
const mongoosePaginate = require("mongoose-paginate-v2");


const passwordSchema = new mongoose.Schema({
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
    siteName: {
        type: String,
        required: true,
    },
    siteURL: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    Phone2FA: {
        type: String,
        default: null,
    },
    backupCodes: {
        type: String,
        default: null,
    },
    notes: {
        type: String,
        default: null,
    },
    access: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'members',
        }
    ]
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

passwordSchema.pre("save", async function (next) {
    const that = this;
    const SALT_FACTOR = 5;

    if (!that.isModified("password")) {
        return next();
    }
    return genSalt(that, SALT_FACTOR, next);
});


passwordSchema.methods.comparePassword = function (passwordAttempt, cb) {
    bcrypt.compare(passwordAttempt, this.password, (err, isMatch) =>
        err ? cb(err) : cb(null, isMatch)
    );
};

passwordSchema.plugin(mongoosePaginate);


module.exports = mongoose.model('Password', passwordSchema);
