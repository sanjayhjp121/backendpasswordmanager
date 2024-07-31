const mongoose = require('mongoose')



const paymentHistory = new mongoose.Schema({
    name: {
        type: String
    },
    email: {
        type: String
    },
    phone: {
        type: String
    },
    user_id: {
        type: mongoose.ObjectId,
        ref: 'User'
    },
    transection_id: {
        type: String
    },
    subscription_id: {
        type: mongoose.ObjectId,
        ref: 'plans'
    },
    amount: {
        type: Number
    },
    stripe_invoice: {
        type: String
    }
},
    {
        versionKey: false,
        timestamps: true
    }
)



module.exports = mongoose.model('paymentHistory', paymentHistory)