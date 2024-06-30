const mongoose = require('mongoose');

const passwordSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
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

module.exports = mongoose.model('Password', passwordSchema);
