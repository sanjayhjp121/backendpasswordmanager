const mongoose = require('mongoose');

const passwordRevealLogSchema = new mongoose.Schema({
    action: {
        type: String,
        required: true,
        enum: ['add', 'reveal', 'delete', 'update'],
    },
    user: {
        id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'member',
            required: true
        },
        username: {
            type: String,
            required: true
        }
    },
    agency: {
        type: mongoose.Schema.Types.ObjectId,
            ref: 'agency',
            required: true
    },
    password: {
        type: mongoose.Schema.Types.ObjectId,
            ref: 'Password',
    },
    adminId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    ip: {
        type: String,
        required: true
    },
    browser: {
        type: String,
        required: true
    },
    os: {
        type: String,
        required: true
    },
    location: {
        country: {
            type: String
        },
        region: {
            type: String
        },
        city: {
            type: String
        }
    },
    device: {
        type: String // Mobile, Desktop, Tablet
    },
    network: {
        type: String // WiFi, Ethernet, Cellular
    },
    requestUrl: {
        type: String,
        required: true
    },
    requestMethod: {
        type: String,
        required: true
    },
    responseStatus: {
        type: Number,
        required: true
    },
    responseTime: {
        type: Number,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    metadata: {
        type: Map,
        of: String
    }
});

module.exports = mongoose.model('passwordRevealLog', passwordRevealLogSchema);
