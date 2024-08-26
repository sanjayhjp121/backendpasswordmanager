const mongoose = require('mongoose')
const validator = require('validator')
const mongoosePaginate = require('mongoose-paginate-v2')

const plans = new mongoose.Schema(
  {
    price_id: {
      type: String,
      required: false
    },
    name: {
      type: String,
    },
    description: {
      type: String
    },
    price: {
      type: Number,
      required: false
    },
    duration: {
      type: String
    },
    features: [{
      type: String
    }],
  },
  {
    versionKey: false,
    timestamps: true
  }
)

plans.plugin(mongoosePaginate)
module.exports = mongoose.model('plans', plans)