const nodemailer = require("nodemailer");
const mg = require("nodemailer-mailgun-transport");
// const i18n = require("i18n");
const User = require("../models/user");
// const Admin = require("../models/admin");
const { itemAlreadyExists, itemExists } = require("./utils");
const express = require("express");
var jwt = require("jsonwebtoken");
var path = require("path");
const app = express();
// const APP_NAME = process.env.APP_NAME;
const { capitalizeFirstLetter } = require("./helpers");
// const ejs = require("ejs");
// var pdf = require("html-pdf");
// var mime = require("mime-types");
app.set("view engine", "ejs"); // we use ejs
var mailer = require("express-mailer");
// var moment = require("moment");
// var mongoose = require("mongoose");

const {
  handleError,
  getIP,
  buildErrObject,
  getCountryCode,
  sendPushNotification,
} = require("./utils");

mailer.extend(app, {
  from: "testing@gmail.com",
  host: "smtp.gmail.com",
  secureConnection: true,
  port: 465,
  transportMethod: "SMTP",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASS,
  },
});

/**
 * Sends email
 * @param {Object} data - data
 * @param {boolean} callback - callback
 */
const sendEmail = async (data, callback) => {
  const auth = {
    auth: {
      // eslint-disable-next-line camelcase
      api_key: process.env.EMAIL_SMTP_API_MAILGUN,
      domain: process.env.EMAIL_SMTP_DOMAIN_MAILGUN,
    },
  };
  const transporter = nodemailer.createTransport(mg(auth));
  const mailOptions = {
    from: `${process.env.EMAIL_FROM_NAME} <${process.env.EMAIL_FROM_ADDRESS}>`,
    to: `${data.user.name} <${data.user.email}>`,
    subject: data.subject,
    html: data.htmlMessage,
  };
  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      return callback(false);
    }
    return callback(true);
  });
};

/**
 * Prepares to send email
 * @param {string} user - user object
 * @param {string} subject - subject
 * @param {string} htmlMessage - html message
 */
const prepareToSendEmail = (user, subject, htmlMessage) => {
  user = {
    name: user.name,
    email: user.email,
    verification: user.verification,
  };
  const data = {
    user,
    subject,
    htmlMessage,
  };
  if (process.env.NODE_ENV === "production") {
    sendEmail(data, (messageSent) =>
      messageSent
        ? console.log(`Email SENT to: ${user.email}`)
        : console.log(`Email FAILED to: ${user.email}`)
    );
  } else if (process.env.NODE_ENV === "development") {
    console.log(data);
  }
};

module.exports = {
  /**
   * Checks User model if user with an specific email exists
   * @param {string} email - user email
   * @param {Boolean} throwError - whenther to throw error or not
   */
  async emailExists(email, throwError = false) {
    return new Promise((resolve, reject) => {
      User.findOne({
        email: email,
      })
        .then((item) => {
          resolve(item ? true : false);
        })
        .catch((err) => {
          resolve(false);
        });
    });
  },


  async socialIdExists(model, social_id, social_type, throwError = false) {
    return new Promise((resolve, reject) => {
      model.findOne({
        social_id: social_id,
        social_type: social_type,
      })
        .then((item) => {
          var err = null;
          if (throwError) {
            itemAlreadyExists(err, item, reject, "USER ALREADY EXISTS");
          }
          resolve(item ? true : false);
        })
        .catch((err) => {
          var item = null;
          itemAlreadyExists(err, item, reject, "ERROR");
          resolve(false);
        });
    });
  },

  async userExists(model, email, throwError = true) {
    return new Promise((resolve, reject) => {
      model.findOne({
        email: email
      })
        .then((item) => {
          var err = null;
          if (throwError) {
            itemAlreadyExists(err, item, reject, "EMAIL ALREADY EXISTS");
          }
          resolve(item ? item : false);
        })
        .catch((err) => {
          var item = null;
          itemAlreadyExists(err, item, reject, "ERROR");
          resolve(false);
        });
    });
  },

  async checkMobileExists(phone_number, throwError = false) {
    return new Promise((resolve, reject) => {
      User.findOne({
        phone_number: phone_number,
      })
        .then((item) => {
          var err = null;
          resolve(item ? true : false);
        })
        .catch((err) => {
          var item = null;
          resolve(false);
        });
    });
  },


  /**
   * Checks User model if user with an specific username exists
   * @param {string} username - user username
   * @param {Boolean} throwError - whenther to throw error or not
   */

  async usernameExists(username, throwError = false) {
    return new Promise((resolve, reject) => {
      User.findOne({
        username: username,
      })
        .then((item) => {
          var err = null;
          if (throwError) {
            itemAlreadyExists(err, item, reject, "USERNAME ALREADY EXISTS");
          }
          resolve(item ? true : false);
        })
        .catch((err) => {
          var item = null;
          itemAlreadyExists(err, item, reject, "ERROR");
          resolve(false);
        });
    });
  },

  /**
   * Checks Admin model if admin with an specific email exists
   * @param {string} email - admin email
   * @param {Boolean} throwError - whenther to throw error or not
   */
  async adminEmailExists(email, throwError = false) {
    return new Promise((resolve, reject) => {
      Admin.findOne({
        email: email,
      })
        .then((item) => {
          var err = null;
          if (throwError) {
            itemAlreadyExists(err, item, reject, "EMAIL ALREADY EXISTS");
          }
          resolve(item ? true : false);
        })
        .catch((err) => {
          var item = null;
          itemAlreadyExists(err, item, reject, "ERROR");
          resolve(false);
        });
    });
  },

  /**
   * Checks User model if user with an specific email exists but excluding user id
   * @param {string} id - user id
   * @param {string} email - user email
   */
  async emailExistsExcludingMyself(id, email) {
    return new Promise((resolve, reject) => {
      User.findOne(
        {
          email,
          _id: {
            $ne: id,
          },
        },
        (err, item) => {
          itemAlreadyExists(err, item, reject, "EMAIL_ALREADY_EXISTS");
          resolve(false);
        }
      );
    });
  },

  /**
   * Checks User model if user with an specific mobile exists but excluding user id
   * @param {string} id - user id
   * @param {string} email - user email
   */
  async checkMobileExistsExcludingMyself(id, phone_no) {
    return new Promise((resolve, reject) => {
      model.User.findOne({
        where: {
          phone_no: phone_no,
          id: {
            [Op.not]: id,
          },
        },
      }).then((item) => {
        if (item) {
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });
  },
  /**
   * Sends email common
   * @param {string} locale - locale
   * @param {Object} mailOptions - mailOptions object
   * @param {string} template - template
   */

  async sendEmail(locale, mailOptions, template) {
    mailOptions.website_url = process.env.FRONTEND_PROD_URL;
    console.log("mailOptions", mailOptions)
    console.log("template", template)
    locale = locale == null ? "" : `${locale}/`

    console.log("`${locale}${template}`", `${locale}${template}`)
    app.mailer.send(
      `${locale}${template}`,
      mailOptions,
      function (err, message) {
        if (err) {
          console.log("There was an error sending the email" + err);
        } else {
          console.log("Mail sent");
        }
      }
    );
  },

  /**
   * Sends reset password email
   * @param {string} locale - locale
   * @param {Object} user - user object
   */

  async sendResetPasswordEmailMessage(locale, user) {
    i18n.setLocale(locale);
    const subject = i18n.__("forgotPassword.SUBJECT");
    const htmlMessage = i18n.__(
      "forgotPassword.MESSAGE",
      user.email,
      process.env.FRONTEND_URL,
      user.verification
    );
    prepareToSendEmail(user, subject, htmlMessage);
  },

  async sendVerificationEmail(user, template) {
    return new Promise(async (resolve, reject) => {
      try {
        user = JSON.parse(JSON.stringify(user));
        // const token = jwt.sign(
        //   {
        //     data: user._id,
        //   },
        //   process.env.JWT_SECRET,
        //   { expiresIn: "24h" }
        // );
        if (!user.full_name) {
          user.full_name = "user";
        }

        console.log("verification_link", user.verification_link)
        app.mailer.send(
          `${template}`,
          {
            to: user.email,
            subject: `Verify Email - ${APP_NAME}`,
            name: `${capitalizeFirstLetter(user.full_name)}`,
            verification_code: user.verification,
            // verification_link: `${process.env.SERVER_URL}auth/verifyEmail/${token}`,
            verification_link: user.verification_link,
            website_url: process.env.FRONTEND_PROD_URL,
          },
          function (err) {
            if (err) {
              console.log("There was an error sending the email" + err);
              reject(buildErrObject(422, err.message));
            } else {
              console.log("VERIFICATION EMAIL SENT");
              resolve(true);
            }
          }
        );
      } catch (err) {
        reject(buildErrObject(422, err.message));
      }
    });
  },


  async sendBookingEmail(data, template) {
    return new Promise(async (resolve, reject) => {
      try {
        data = JSON.parse(JSON.stringify(data));
        if (!data.full_name) {
          data.full_name = "user";
        }

        app.mailer.send(
          `${template}`,
          {
            ...data,
            website_url: process.env.FRONTEND_PROD_URL,
          },
          function (err) {
            if (err) {
              console.log("There was an error sending the email" + err);
              reject(buildErrObject(422, err.message));
            } else {
              console.log("BOOKING EMAIL SENT");
              resolve(true);
            }
          }
        );
      } catch (err) {
        reject(buildErrObject(422, err.message));
      }
    });
  },

  async sendAccountCreationEmail(user, template) {
    return new Promise(async (resolve, reject) => {
      try {
        user = JSON.parse(JSON.stringify(user));

        if (!user.full_name) {
          user.full_name = "user";
        }

        app.mailer.send(
          `${template}`,
          {
            to: user.email,
            subject: `Accounted Created - ${APP_NAME}`,
            name: `${capitalizeFirstLetter(user.full_name)}`,
            email: user.email,
            password: user.password,
            website_url: process.env.FRONTEND_PROD_URL,
          },
          function (err) {
            if (err) {
              console.log("There was an error sending the email" + err);
              reject(buildErrObject(422, err.message));
            } else {
              console.log("VERIFICATION EMAIL SENT");
              resolve(true);
            }
          }
        );
      } catch (err) {
        reject(buildErrObject(422, err.message));
      }
    });
  },

  async sendContactUsEmail(user, template) {
    return new Promise(async (resolve, reject) => {
      try {
        user = JSON.parse(JSON.stringify(user));

        if (!user.full_name) {
          user.full_name = "user";
        }

        app.mailer.send(
          `${template}`,
          {
            to: user.email,
            subject: "New Contact Form Submission",
            name: `${capitalizeFirstLetter(user.full_name)}`,
            email: user.email,
            title: user.title,
            user_email: user.user_email,
            description: user.description,
            website_url: process.env.FRONTEND_PROD_URL,
          },
          function (err) {
            if (err) {
              console.log("There was an error sending the email" + err);
              reject(buildErrObject(422, err.message));
            } else {
              console.log("VERIFICATION EMAIL SENT");
              resolve(true);
            }
          }
        );
      } catch (err) {
        reject(buildErrObject(422, err.message));
      }
    });
  },

  async sendForgetPasswordEmail(locale, user, template) {


    return new Promise(async (resolve, reject) => {

      try {
        user = JSON.parse(JSON.stringify(user));
        const token = jwt.sign(
          {
            // sign the jwt token wiht the user id
            data: user._id,
          },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        console.log("Inside emailer");
        if (!user.first_name) {
          user.first_name = "user";
        }

        if (!user.last_name) {
          user.last_name = "";
        }


        app.mailer.send(
          `${locale}/${template}`,
          {
            to: user.email,
            subject: `Change Password - ${APP_NAME}`,
            name: `${capitalizeFirstLetter(
              user.first_name
            )} ${capitalizeFirstLetter(user.last_name)}`,
            verification_code: "",
            verification_link: `${process.env.SERVER_URL}admin/changePasswordPage/${token}`,
            website_url: process.env.FRONTEND_PROD_URL,
          },
          function (err) {
            if (err) {
              console.log("There was an error sending the email" + err);
              reject(buildErrObject(422, err.message));
            } else {
              console.log("VERIFICATION EMAIL SENT");
              resolve("VERIFICATION EMAIL SENT");
            }

          }
        );

      } catch (err) {
        reject(buildErrObject(422, err.message));
      }

    })



  },

  async sendOtpInEmail(locale, data, template) {
    console.log("template", template);
    // mailOptions.website_url = process.env.WEBSITE_URL
    app.mailer.send(
      `${locale}/${template}`,
      {
        // email view path
        to: data.email,
        subject: `Verify Email - ${APP_NAME}`,
        // name: `${capitalizeFirstLetter(user.first_name)} ${capitalizeFirstLetter(user.last_name)}`,
        name: "test",
        OTP: data.otp_for_verification,
        website_url: process.env.FRONTEND_PROD_URL,
        Image_url: process.env.STORAGE_PATH_HTTP,
      },
      function (err) {
        if (err) {
          console.log("There was an error sending the email" + err);
        }
        console.log("VERIFICATION EMAIL SENT");
        return true;
      }
    );
  },



  async sendCodeInEmail(locale, data, template) {
    console.log("template", data);

    app.mailer.send(
      `${locale}/${template}`,
      {
        // email view path
        to: data.email,
        // to: 'promatics.ajay.k@gmail.com',
        subject: `Generated code - ${APP_NAME}`,
        // name: `${capitalizeFirstLetter(user.first_name)} ${capitalizeFirstLetter(user.last_name)}`,
        name: "test",
        CODE: data.code,
        website_url: process.env.FRONTEND_PROD_URL,
        Image_url: process.env.STORAGE_PATH_HTTP,
      },
      function (err) {
        if (err) {
          console.log("There was an error sending the email" + err);
        }
        console.log("CODE SENT");
        return true;
      }
    );
  },

  async sendOtpForCompleteOrder(locale, data, template) {
    console.log("template", data);

    app.mailer.send(
      `${locale}/${template}`,
      {
        // email view path
        to: data.professional_id.email,
        // to: 'promatics.ajay.k@gmail.com',
        subject: `Verification Otp For Complete Order - ${APP_NAME}`,
        // name: `${capitalizeFirstLetter(user.first_name)} ${capitalizeFirstLetter(user.last_name)}`,
        name: "test",
        CODE: data.code,
        website_url: process.env.FRONTEND_PROD_URL,
        Image_url: process.env.STORAGE_PATH_HTTP,
      },
      function (err) {
        if (err) {
          console.log("There was an error sending the email" + err);
        }
        console.log("CODE SENT");
        return true;
      }
    );
  },
};
