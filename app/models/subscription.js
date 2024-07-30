const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");
const validator = require("validator");
const mongoosePaginate = require("mongoose-paginate-v2");

const subescriptionSchema = new mongoose.Schema(
    {
        user_id: {
            type: mongoose.ObjectId,
            ref: 'users'
        },
        type: {
            type: String,
        },
        username:{
            type: String
        },
        password :{
            type: String,
        },
        expiration_date: {
            type: Date,
            required: true,
        },
    },
    {
        timestamps: true,
    }
);


subescriptionSchema.plugin(mongoosePaginate);

module.exports = mongoose.model("subescription", subescriptionSchema);
