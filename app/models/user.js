const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");
const validator = require("validator");
const mongoosePaginate = require("mongoose-paginate-v2");

const UserSchema = new mongoose.Schema(
    {
        profile_image: {
            type: String
        },
        unique_id: {
            type: Number,
            unique: true,
        },
        full_name: {
            type: String,
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
        phone_number: {
            type: String,
            unique: true,
            required: true
        },
        dob:{
            type: String
        },
        description :{
            type: String
        },
        company_name: {
            type: String
        },
        company_address: {
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
        password: {
            type: String,
            required: true,
            select: false
        },
        decoded_password: {
            type: String,
            select: false
        },
        role: {
            type: String,
            enum: ["user"],
            default: "user",
            required: true
        },
        is_subescribed: {
            type: Boolean,
            default: false
        },
        status: {
            type: String,
            enum: ["active", "inactive"],
            default: "active"
        },
        plan: {
            type: String,
            enum: ['basic', 'mini', 'agency'],
            default: 'basic',
        },
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
        exists = await mongoose.models.users.findOne({ unique_id: uniqueId });
    }
    return uniqueId;
};


UserSchema.pre("save", async function (next) {
    const that = this;
    const SALT_FACTOR = 5;

    if (!this.unique_id) {
        this.unique_id = await generateUniqueCode();
    }

    this.decoded_password = this.password

    if (!that.isModified("password")) {
        return next();
    }
    return genSalt(that, SALT_FACTOR, next);
});


UserSchema.methods.comparePassword = function (passwordAttempt, cb) {
    bcrypt.compare(passwordAttempt, this.password, (err, isMatch) =>
        err ? cb(err) : cb(null, isMatch)
    );
};

UserSchema.plugin(mongoosePaginate);

module.exports = mongoose.model("users", UserSchema);
