const mongoose = require('mongoose')
// const requestIp = require('request-ip')
const { validationResult } = require('express-validator')
// const { admin } = require("../config/firebase")
const moment = require("moment")
const { capitalizeFirstLetter } = require("./helpers")

const crypto = require('crypto')
const secret = process.env.JWT_SECRET
const algorithm = 'aes-256-cbc'
const key = crypto.scryptSync(secret, 'salt', 32)
const iv = Buffer.alloc(16, 0) // Initialization crypto vector
var bcrypt = require('bcrypt');

const { isArray } = require('util')
/**
 * Removes extension from file
 * @param {string} file - filename
 */
exports.removeExtensionFromFile = file => {
  return file
    .split('.')
    .slice(0, -1)
    .join('.')
    .toString()
}

/**
 * Gets IP from user
 * @param {*} req - request object
 */
exports.getIP = req => requestIp.getClientIp(req)

/**
 * Gets browser info from user
 * @param {*} req - request object
 */
exports.getBrowserInfo = req => req.headers['user-agent']

/**
 * Gets country from user using CloudFlare header 'cf-ipcountry'
 * @param {*} req - request object
 */
exports.getCountry = req =>
  req.headers['cf-ipcountry'] ? req.headers['cf-ipcountry'] : 'XX'

/**
 * Handles error by printing to console in development env and builds and sends an error response
 * @param {Object} res - response object
 * @param {Object} err - error object
 */
exports.handleError = (res, err) => {
  // Prints error in console
  if (process.env.NODE_ENV === 'development') {
    console.log(err)
  }
  // Sends error to user
  res.status(err?.code ?? 500 ).json({
    errors: {
      msg: err.message
    },
    code: err?.code ?? 500
  })
}

/**
 * Builds error object
 * @param {number} code - error code
 * @param {string} message - error text
 */

exports.buildErrObject = (code, message) => {
  return {
    code,
    message
  }
}

/**
 * Builds error for validation files
 * @param {Object} req - request object
 * @param {Object} res - response object
 * @param {Object} next - next object
 */
exports.validationResult = (req, res, next) => {
  try {
    validationResult(req).throw()
    if (req.body.email) {
      req.body.email = req.body.email.toLowerCase()
    }
    return next()
  } catch (err) {
    return this.handleError(res, this.buildErrObject(422, err.array()))
  }
}

/**
 * Builds success object
 * @param {string} message - success text
 */
exports.buildSuccObject = message => {
  return {
    msg: message
  }
}

/**
 * Checks if given ID is good for MongoDB
 * @param {string} id - id to check
 */
exports.isIDGood = async id => {
  return new Promise((resolve, reject) => {
    const goodID = mongoose.Types.ObjectId.isValid(id)
    return goodID
      ? resolve(id)
      : reject(this.buildErrObject(422, 'ID_MALFORMED'))
  })
}

/**
 * Item not found
 * @param {Object} err - error object
 * @param {Object} item - item result object
 * @param {Object} reject - reject object
 * @param {string} message - message
 */
exports.itemNotFound = (err, item, reject, message) => {
  if (err) {
    reject(this.buildErrObject(422, err.message))
  }
  if (!item) {
    reject(this.buildErrObject(404, message))
  }
}

/**
 * Item already exists
 * @param {Object} err - error object
 * @param {Object} item - item result object
 * @param {Object} reject - reject object
 * @param {string} message - message
 */
exports.itemAlreadyExists = (err, item, reject, message) => {
  console.log(item);
  if (err) {
    reject(this.buildErrObject(422, err.message))
  }
  if (item) {
    reject(this.buildErrObject(422, message))
  }
}

exports.itemExists = (err, item, reject, message) => {
  if (err) {
    reject(this.buildErrObject(422, err.message))
  }
  if (!item) {
    reject(this.buildErrObject(422, message))
  }
}

exports.objectToQueryString = async obj => {
  return new Promise((resolve, reject) => {
    const searchParams = new URLSearchParams();
    const params = obj;
    Object.keys(params).forEach(key => searchParams.append(key, params[key]));
    resolve(searchParams.toString())
  })
}

/**
 * Fetch country code from data
 * @param {Object} obj - Country Info
 */
exports.getCountryCode = obj => {
  return {
    country_code: obj.country
  }
}

/**
 * Notification 
 */

exports.sendPushNotification = async (
  tokens,
  title,
  message,
  notificationData
) => {
  try {
    if (notificationData.sender_id)
      notificationData.sender_id = notificationData.sender_id.toString();

    if (notificationData.receiver_id)
      notificationData.receiver_id = notificationData.receiver_id.toString();
    if (notificationData.value_id)
      notificationData.value_id = notificationData.value_id.toString();
    const notification = {
      title: title,
      description: message,
      // image: notificationData.icon
      //   ? notificationData.icon
      //   : `${process.env.NOTIFICATION_ICONS_PATH}/default.ico`,
    };
    var message = {
      notification: notification,
      data: notificationData,
      tokens: tokens,
    };
    // console.log("final message", message);
    admin
      .messaging()
      .sendMulticast(message)
      .then((response) => {
        console.log("response", response);
        if (response.failureCount > 0) {
          const failedTokens = [];
          response.responses.forEach((resp, idx) => {
            // console.log("resp-->", resp);
            // console.log("idx-->", idx);
            if (!resp.success) {
              failedTokens.push(tokens[idx]);
            }
          });
          console.log("List of tokens that caused failures: " + failedTokens);
        }
      })
      .catch((error) => {
        console.log("Error sending message:", error);
      });
  } catch (err) {
    console.log(err);
    return false;
  }
};


exports.sendIosPushNotification = async (
  tokens,
  title,
  message,
  notificationData
) => {
  try {
    if (notificationData.sender_id)
      notificationData.sender_id = notificationData.sender_id.toString();

    if (notificationData.receiver_id)
      notificationData.receiver_id = notificationData.receiver_id.toString();
    if (notificationData.value_id)
      notificationData.value_id = notificationData.value_id.toString();
    const notification = {
      title: title,
      body: message,
      // image: notificationData.icon
      //   ? notificationData.icon
      //   : `${process.env.NOTIFICATION_ICONS_PATH}/default.ico`,
    };
    var message = {
      notification: notification,
      data: notificationData,
      tokens: tokens,
    };
    console.log("final message  Insside IOs ", message);
    admin
      .messaging()
      .sendMulticast(message)
      .then((response) => {
        console.log("response", response);
        if (response.failureCount > 0) {
          const failedTokens = [];
          response.responses.forEach((resp, idx) => {
            // console.log("resp-->", resp);
            // console.log("idx-->", idx);
            if (!resp.success) {
              failedTokens.push(tokens[idx]);
            }
          });
          console.log("List of tokens that caused failures: " + failedTokens);
        }
      })
      .catch((error) => {
        console.log("Error sending message:", error);
      });
  } catch (err) {
    console.log(err);
    return false;
  }
};

exports.sendAndroidPushNotification = async (
  tokens,
  title,
  body,
  notificationData
) => {
  try {
    console.log("tokens", tokens);
    if (notificationData.sender_id)
      notificationData.sender_id = notificationData.sender_id.toString();

    if (notificationData.receiver_id)
      notificationData.receiver_id = notificationData.receiver_id.toString();
    if (notificationData.value_id)
      notificationData.value_id = notificationData.value_id.toString();
    const notification = {
      title: title,
      body: body,
      // image: notificationData.icon
      //   ? notificationData.icon
      //   : `${process.env.NOTIFICATION_ICONS_PATH}/default.ico`,
    };
    var message = {
      notification: notification,
      data: notificationData,
      tokens: tokens,
    };
    // console.log("final message", message);
    admin
      .messaging()
      .sendMulticast(message)
      .then((response) => {
        console.log("response", response);
        if (response.failureCount > 0) {
          const failedTokens = [];
          response.responses.forEach((resp, idx) => {
            console.log("resp failures-->", resp);
            // console.log("idx-->", idx);
            if (!resp.success) {
              failedTokens.push(tokens[idx]);
            }
          });
          console.log("List of tokens that caused failures: " + failedTokens);
        }
      })
      .catch((error) => {
        console.log("Error sending message:", error);
      });
  } catch (err) {
    console.log(err);
    return false;
  }
};



/**
 * Checks is password matches
 * @param {string} password - password
 * @param {Object} user - user object
 * @returns {boolean}
 */

exports.checkPassword = async (password, user) => {
  return new Promise((resolve, reject) => {
    user.comparePassword(password, (err, isMatch) => {
      if (err) {
        console.log('err---->', err);
        reject(this.buildErrObject(422, err.message))
      }
      console.log('isMatch--xxxxxxxxx-------->', isMatch);
      if (!isMatch) {
        resolve(false)
      }
      resolve(true)
    })
  })
}

/**
 * Encrypts text
 * @param {string} text - text to encrypt
*/

exports.encrypt = (text) => {
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  let encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}

/**
 * Decrypts text
 * @param {string} text - text to decrypt
*/

exports.decrypt = (text) => {
  const decipher = crypto.createDecipheriv(algorithm, key, iv)
  try {
    let decrypted = decipher.update(text, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  } catch (err) {
    return err
  }
}

exports.generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000);
}