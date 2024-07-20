const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");
const validator = require("validator");
const mongoosePaginate = require("mongoose-paginate-v2");

const agencySchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.ObjectId,
            ref: 'users'
        },
        name: {
            type: String,
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
    },
    {
        timestamps: true,
    }
);



agencySchema.plugin(mongoosePaginate);

module.exports = mongoose.model("agency", agencySchema);
