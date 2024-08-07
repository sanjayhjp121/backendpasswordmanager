const utils = require("../utils/utils")
// const ResetPassword = require("../../models/reset_password")
const uuid = require('uuid');
const emailer = require("../utils/emailer");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken")

const vaultsModel = require('../models/vault')
const memberModel = require('../models/member')
const passwordModel = require("../models/password")
const User = require("../models/user");
const Admin = require("../models/admin");
const agencyModel = require("../models/agency")
const stripe = require('stripe')(process.env.Stripe_Key)
const Plans = require("../models/plans")
const paymentHistory = require("../models/paymentHistory")

const generateToken = (_id, remember_me) => {
  const expiration = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * (remember_me === true ? process.env.JWT_EXPIRATION_DAY_FOR_REMEMBER_ME : process.env.JWT_EXPIRATION_DAY));

  // returns signed and encrypted token
  return utils.encrypt(
    jwt.sign(
      {
        data: {
          _id,
          type: 'superadmin'
        },
        exp: expiration
      },
      process.env.JWT_SECRET
    )
  )
}



// const setUserInfo = req => {
//   let user = {
//     id: req.id,
//     first_name: req.first_name,
//     last_name: req.last_name,
//     email: req.email,
//     // role: req.role,
//     //verified: req.verified
//   }
//   // Adds verification for testing purposes
//   if (process.env.NODE_ENV !== 'production') {
//     user = {
//       ...user,
//       verification: req.verification
//     }
//   }
//   return user
// }



// const saveUserAccessAndReturnToken = async (req, user, remember_me) => {
//   return new Promise((resolve, reject) => {
//     const userAccess = new UserAccess({
//       email: user.email,
//       ip: utils.getIP(req),
//       browser: utils.getBrowserInfo(req),
//       country: utils.getCountry(req),
//     })
//     userAccess.save((err) => {
//       if (err) {
//         reject(utils.buildErrObject(422, err.message));
//       }
//       setUserInfo(user);
//       resolve({
//         token: generateToken(user._id, user.role, remember_me),
//         user: user,
//         code: 200
//       })
//     });
//   })
// }

exports.addAdmin = async (req, res) => {
  try {
    const data = {
      full_name: "Bishwjeet",
      email: "bishwjeetkumar7250@gmail.com",
      password: "1234",
      phone_number: "+919304989643",
      role: "superadmin",
    }

    const item = new Admin(data)
    await item.save();
    return res.status(200).json(item);
  } catch (error) {
    console.log(error);
    utils.handleError(res, error);
  }
};


exports.login = async (req, res) => {
  try {
    const { email, password, remember_me } = req.body;
    const user = await Admin.findOne({ email: email }, "+password");
    if (!user) return utils.handleError(res, { message: "Invalid login credentials. Please try again", code: 400 })

    const isPasswordMatch = await utils.checkPassword(password, user)
    console.log("isPasswordMatch", isPasswordMatch)
    if (!isPasswordMatch) {
      return utils.handleError(res, { message: "Invalid login credentials. Please try again", code: 400 })
    }

    let userObj = user.toJSON();
    delete userObj.password;

    const token = generateToken(user._id, remember_me);
    res.json({ code: 200, data: { user: userObj, token } })
  } catch (error) {
    utils.handleError(res, error)
  }
}

exports.forgotPassword = async (req, res) => {

  try {
    const { email, production } = req.body;

    let user = await Admin.findOne({ email });
    if (!user) return utils.handleError(res, { message: "No account found with the provided information", code: 400 });

    const token = uuid.v4();

    const tokenExpirationDuration = 5 * 60;
    const resetInstance = new ResetPassword({
      email: email,
      token: token,
      used: false,
      exp_time: new Date(Date.now() + tokenExpirationDuration * 1000)
    });

    //Save the resetInstance to the database
    await resetInstance.save();
    const mailOptions = {
      to: user.email,
      subject: "Password Reset Request",
      name: user.full_name,
      email: user.email,
      reset_link: production === false ? `${process.env.LOCAL_FRONTEND_URL}ui/Resetpassword/${token}` : `${process.env.PRODUCTION_FRONTEND_URL}ui/Resetpassword/${token}`
    }

    emailer.sendEmail(null, mailOptions, "forgotPasswordWithLink");

    return res.json({
      code: 200,
      message: "Reset link has been sent to your email",
    });

  } catch (err) {
    console.log(err)
    utils.handleError(res, err)
  }

}


exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;
    const reset = await ResetPassword.findOne({ token: token });

    // Check if the reset token exists and if it's flagged as used
    if (!reset || reset.used) {
      return utils.handleError(res, { message: 'Invalid or expired reset password token', code: 400 })
    }

    // Check if the token has expired
    if (reset.exp_time < new Date()) {
      return utils.handleError(res, { message: 'Reset password token has expired', code: 400 })
    }

    // Find the user associated with the reset token
    const user = await Admin.findOne({ email: reset.email });

    user.password = password;
    await user.save();

    // Reset the token flag and time
    reset.used = true;
    reset.time = undefined;
    await reset.save();

    res.json({ message: 'Your password has been successfully reset', code: 200 });
  } catch (err) {
    console.error(err);
    utils.handleError(res, err)
  }
};



exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user_id = req.user._id

    let user = await Admin.findById(user_id, "+password");
    const isPasswordMatch = await utils.checkPassword(currentPassword, user);
    if (!isPasswordMatch) return utils.handleError(res, { message: "Current password is incorrect", code: 400 });

    const newPasswordMatch = await utils.checkPassword(newPassword, user);
    if (newPasswordMatch) return utils.handleError(res, { message: "New password must be different from the current password", code: 400 });

    user.password = newPassword;

    await user.save();

    res.status(200).json({ message: 'Password has been changed successfully', code: 200 });
  } catch (error) {
    utils.handleError(res, error);
  }
};


exports.getUserList = async (req, res) => {
  try {
    const { search, limit = 10, offset = 0 } = req.query;
    const query = {};

    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { company_name: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .skip(parseInt(offset))
      .limit(parseInt(limit));

    const totalCount = await User.countDocuments(query);

    return res.status(200).json({
      data: users,
      totalCount: totalCount,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};



exports.getUserDetail = async (req, res) => {
  try {
    const userId = req.query.userId;
    const user = await User.findOne({ _id: new mongoose.Types.ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const passwords = await passwordModel.find({ user: user._id });

    return res.status(200).json({
      data: user,
      passwords: passwords,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};



exports.numberOfAgency = async (req, res) => {
  try {
    const agencyCount = await agencyModel.countDocuments({});

    return res.status(200).json({
      data: agencyCount,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};




// --------------------- STRIPE ---------------------------------------

exports.createPriceGroup = async (req, res) => {
  try {
    const data = req.body;

    if (!data.name) {
      throw new Error("Product name is required");
    }
    if (!data.price) {
      throw new Error("Product amount is required");
    }
    if (isNaN(data.price) || data.price <= 0) {
      throw new Error("Product amount must be a valid number greater than 0");
    }

    const parsedPrice = parseInt(data.price);
    if (isNaN(parsedPrice)) {
      throw new Error("Parsed product amount is not a valid number");
    }

    const product = await stripe.products.create({
      name: data.name,
      tax_code: "txcd_10102001"
    });

    const price = await stripe.prices.create({
      product: product.id,
      unit_amount: (parsedPrice * 100),
      currency: 'usd',
      recurring: {
        interval: 'month',
        interval_count: parseInt(data.duration)
      },
    });

    const obj = {
      price_id: price.id,
      name: data.name,
      price: parsedPrice,
      duration: data.duration,
      description: data.description,
      features: data.features
    };

    const resp = await Plans.create(obj);
    return res.status(200).json({ code: 200, data: resp });
  } catch (error) {
    console.log(error);
    let statusCode = 500;
    let message = 'Internal Server Error';

    if (error.type === 'StripeInvalidRequestError') {
      statusCode = 400;
      message = error.message;
    } else if (error.message === "Product name is required" ||
      error.message === "Product amount is required" ||
      error.message === "Product amount must be a valid number greater than 0" ||
      error.message === "Parsed product amount is not a valid number") {
      statusCode = 400;
      message = error.message;
    }

    return res.status(statusCode).json({ code: statusCode, message: message });
  }
};



exports.updatePlan = async (req, res) => {
  try {
    const { _id, price_id, name, price, duration, description, features } = req.body;

    if (!_id || !price_id || !name || isNaN(price) || price <= 0) {
      throw new Error("Missing or invalid fields in the request");
    }

    const newPrice = await stripe.prices.create({
      product: (await stripe.prices.retrieve(price_id)).product,
      unit_amount: parseInt(price) * 100,
      currency: 'usd',
      recurring: {
        interval: 'month',
      },
    });

    const updatedPlan = await Plans.findByIdAndUpdate(_id, {
      price_id: newPrice.id,
      name,
      price: parseInt(price),
      duration,
      description,
      features,
      updatedAt: new Date()
    }, { new: true });

    if (!updatedPlan) {
      return res.status(404).json({ code: 404, message: "Plan not found" });
    }

    return res.status(200).json({ code: 200, data: updatedPlan });
  } catch (error) {
    console.log(error);
    let statusCode = 500;
    let message = 'Internal Server Error';

    if (error.type === 'StripeInvalidRequestError') {
      statusCode = 400;
      message = error.message;
    } else if (error.message === "Missing or invalid fields in the request") {
      statusCode = 400;
      message = error.message;
    }

    return res.status(statusCode).json({ code: statusCode, message: message });
  }
};

exports.getAllPlans = async (req, res) => {
  try {
    const data = await Plans.find({});

    const count = await Plans.countDocuments({});

    return res.status(200).json({ data: data, count: count });
  } catch (error) {
    console.log(error);
    handleError(res, error);
  }
}


exports.updatePlansById = async (req, res) => {
  try {
    const data = req.body;
    if (!data._id) {
      return res.status(400).json({ message: "Id is required" });
    }

    const updatedPlan = await Plans.findOneAndUpdate(
      { _id: mongoose.Types.ObjectId(data._id) },
      { $set: data },
      { new: true }
    );

    if (!updatedPlan) {
      return res.status(404).json({ message: "Plan not found" });
    }

    return res.status(200).json({ message: "Plan updated successfully", updatedPlan });
  } catch (error) {
    console.log(error);
    handleError(res, error);
  }
};


exports.getPlanDetail = async (req, res) => {
  try {
    //const id = req.query.id

    const resp = await Plans.findOne({ _id: new mongoose.Types.ObjectId(req.query.id) })

    return res.status(200).json({ code: 200, data: resp })
  } catch (error) {
    console.log(error);
    handleError(res, error);
  }

}


exports.getpaymentHistory = async (req, res) => {
  try {
    //const id = req.query.id
    // const data = req.body
    // const resp = await paymentHistory.find({}).populate("subscription_id").sort({ createdAt: -1 })
    //     .skip(parseInt(data.offset) || 0)
    //     .limit(parseInt(data.limit) || Number.MAX_SAFE_INTEGER).lean()
    // const count = await paymentHistory.countDocuments({});


    const { search, limit = 10, offset = 0 } = req.query;
    let pipeline = [
      {
        $lookup: {
          from: "users",
          localField: "user_id",
          foreignField: "_id",
          as: "user_details",
          pipeline: [
            {
              $project: { _id: 1, full_name: 1, createdAt: 1 }
            }
          ]
        }
      },
      { $unwind: "$user_details" },
      {
        $lookup: {
          from: "plans",
          localField: "subscription_id",
          foreignField: "_id",
          as: "subscription_id"
        }
      },

      { $unwind: "$subscription_id" },
    ];

    if (search) {
      pipeline.push({
        $match: {
          "user_details.full_name": { $regex: search, $options: 'i' }
        }
      });
    }

    pipeline.push({
      $sort: {
        createdAt: -1
      }
    });

    pipeline.push({
      $skip: parseInt(offset)
    });

    pipeline.push({
      $limit: parseInt(limit)
    });

    const data = await paymentHistory.aggregate(pipeline);

    const countPipeline = [];

    if (search) {
      countPipeline.push({
        $match: {
          full_name: { $regex: search, $options: 'i' }
        }
      });
    }

    const totalCountResult = await paymentHistory.aggregate([
      ...countPipeline,
      { $count: "totalCount" }
    ]);

    const totalCount = totalCountResult.length > 0 ? totalCountResult[0].totalCount : 0;

    return res.status(200).json({ code: 200, data: data, count: totalCount })
  } catch (error) {
    console.log(error);
    //   handleError(res, error);
  }

}



exports.getpaymentHistorybyid = async (req, res) => {
  try {
    const id = req.params.id
    const data = req.body
    const resp = await paymentHistory.findOne({ _id: new mongoose.Types.ObjectId(id) }).populate("subscription_id").lean()
    const count = await paymentHistory.countDocuments({ _id: new mongoose.Types.ObjectId(id) });
    return res.status(200).json({ code: 200, data: resp, count: count })
  } catch (error) {
    console.log(error);
    //   handleError(res, error);
  }

}

exports.dashboard = async (req, res) => {
  try {
    const agencyCount = await agency.countDocuments({});
    const userCount = await memberModel.countDocuments({})
    const passwordCount = await passwordModel.countDocuments({})
    const vaultCount = await vaultsModel.countDocuments({})

    return res.status(200).json({
      agency: agencyCount,
      user: userCount,
      password: passwordCount,
      vault: vaultCount
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};