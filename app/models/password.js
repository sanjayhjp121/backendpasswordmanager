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
        select: false
    },
    iv: {
        type: String,
        required: true,
        select: false
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
    ],
    dob: {
        type:String
    }
},
    {
        timestamps: true,
    }
);


passwordSchema.plugin(mongoosePaginate);


module.exports = mongoose.model('Password', passwordSchema);
