const {
  buildSuccObject,
  buildErrObject,
  itemNotFound,
} = require("./utils");

const { admin } = require("./../../config/firebase");
var mongoose = require("mongoose");

/********************
 * CRUD functions *
********************/

/**
 * Send Notificaton to User 
 * @param {Object} models - Will add models
 * @param {Object} object - will populate title,body and token etc etc
 */
const sendNotification = (model, object) => {
  return new Promise(async (resolve, reject) => {
    try {

      const devices = await model.FCMDevice.find({

        user_id: object.user_id

      })

      console.log(`${devices.length} devices found`)

      for (var i = 0; i < devices.length; i++) {
        const val = devices[i];
        var notification = {
          title: object.title.toString(),
          body: object.body.toString(),
        }

        var data_notification = { ...notification };

        if (object.icon) {
          // notification.icon = object.icon
          data_notification.icon = object.icon
        }



        if (object.custom && Object.keys(object.custom).length > 0) {

          data_notification = { ...data_notification, ...object.custom }

        }

        var message = {
          notification: notification,
          data: data_notification,
          token: val.token
        };

        // console.log(message)

        admin.messaging().send(message)
          .then((response) => {
            // Response is a message ID string.
            console.log('Successfully sent message:', response);
          })
          .catch((error) => {
            console.log('Error sending message:', error);
          });

      }

      resolve(true);

    } catch (err) {
      console.log(err)
      reject(this.buildErrObject(422, err.message))
    }
  })
}

module.exports = {

  /**
   * create item in database
   * @param {string} collection - collection name
   * @param {Object} data - data to create
  */

  async mongo_id(id) {
    return mongoose.Types.ObjectId(id)
  },

  async createItem(collection, data) {
    return new Promise(async (resolve, reject) => {
      try {
        console.log(collection)
        
        const record = await collection.create(data);


        resolve({
          success: true,
          message: "ITEM ADDED SUCCESSFULLY",
          data: record
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    })
  },

  /**
   * create mulyiple items in database
   * @param {string} collection - collection name
   * @param {Object} data - data to create
  */

  async createManyItems(collection, data) {
    return new Promise(async (resolve, reject) => {
      try {
        const record = await collection.insertMany(data);
        resolve({
          success: true,
          message: "ITEMS ADDED SUCCESSFULLY",
          data: record
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    })
  },

  /**
    * updates multiple items
    * @param {string} collection - collection name
    * @param {Object} condition - condition
    * @param {Object} data - data to update
  */

  async updateItems(collection, condition, data) {
    return new Promise((resolve, reject) => {
      collection.updateMany(
        condition,
        data,
        {
          new: true,
          runValidators: true,
        },
        (err, item) => {
          resolve(item);
        }
      );
    });
  },

  /**
    * updates an item
    * @param {string} collection - collection name
    * @param {Object} condition - condition
    * @param {Object} data - data to update
    * @param {Object} additionalOptions - some additional options to run
  */

  async updateItem(collection, condition, data, additionalOptions = {}) {
    return new Promise((resolve, reject) => {
      console.log(data, condition);
      collection.findOneAndUpdate(
        condition,
        data,
        {
          new: true,
          runValidators: true,
          ...additionalOptions
        },
        (err, item) => {
          if (err) {
            return reject(buildErrObject(422, err.message));
          }
          resolve({
            success: true,
            message: `ITEM ${item && item.upsertedId ? 'CREATED' : 'UPDATED'} SUCCESSFULLY`,
            data: item
          });
        }
      );
    });
  },

  /**
    * updates an item in database by id
    * @param {string} collection - collection name
    * @param {string} _id - item id
    * @param {Object} data - data to update
  */

  async updateItemThroughId(collection, _id, data, additionalOptions = {}) {
    console.log('idddd-->>>',_id)
    return new Promise((resolve, reject) => {
      collection.findByIdAndUpdate(
        _id,
        data,
        {
          new: true,
          runValidators: true,
          ...additionalOptions
        },
        (err, item) => {
          itemNotFound(err, item, reject, "NOT_FOUND");
          resolve({
            success: true,
            message: "ITEM UPDATED SUCCESSFULLY",
            data: item
          });
        }
      );
    });
  },

  /**
    * update or create an item in database
    * @param {string} collection - collection name
    * @param {Object} condition - item condition
    * @param {Object} data - data to update or create
  */

  async upsert(collection, condition, data) {
    return new Promise((resolve, reject) => {
      collection.updateOne(condition, data, {
        upsert: true,
        setDefaultsOnInsert: true,
        runValidators: true
      },
        (err, item) => {
          if (err) {
            return reject(buildErrObject(422, err.message));
          }
          resolve({
            success: true,
            message: `ITEM ${item.upsertedId ? 'CREATED' : 'UPDATED'} SUCCESSFULLY`,
            data: item
          });
        }
      );
    });
  },

  /**
   * deletes an item from database by id
   * @param {string} collection - collection name
   * @param {string} _id - id of item
  */

  async deleteItem(collection, _id) {
    return new Promise((resolve, reject) => {
      collection.findByIdAndRemove(_id, (err, item) => {
        itemNotFound(err, item, reject, "NOT_FOUND");
        resolve(buildSuccObject("DELETED"));
      });
    });
  },

  /**
  * deletes many items from database with condition
  * @param {string} collection - collection name
  * @param {Object} condition - condition
 */

  async deleteMany(collection, condition) {
    return new Promise((resolve, reject) => {
      collection.deleteMany(condition, function (err) {
        resolve(buildSuccObject("DELETED"));
      })
    });
  },

  /**
   * Gets item from database by id
   * @param {string} collection - collection name
   * @param {string} _id - item id
   * @param {Boolean} throwError - whether to reject if item not found
   * @param {string} select - whether to select certain fields
  */

  async getItemThroughId(collection, _id, throwError = false, select = '') {
    return new Promise((resolve, reject) => {
      collection.findById(_id, select, (err, item) => {
        if (throwError) {
          itemNotFound(err, item, reject, "NOT_FOUND");
        }
        resolve({
          success: true,
          data: item
        });
      });
    });
  },



  async getItemThroughIdWithPopulate(collection, _id, throwError = false, select = '') {
    return new Promise((resolve, reject) => {
      collection.findById(_id, select, (err, item) => {
        if (throwError) {
          itemNotFound(err, item, reject, "NOT_FOUND");
        }
        resolve({
          success: true,
          data: item
        });
      }).populate('user_id');
    });
  },

  async getItemThroughIdWithPopulate1(collection, _id, throwError = false, select = '', populate) {
    return new Promise((resolve, reject) => {
      collection.findById(_id, select, (err, item) => {
        if (throwError) {
          itemNotFound(err, item, reject, "NOT_FOUND");
        }
        resolve({
          success: true,
          data: item
        });
      }).populate('populate');
    });
  },


  /**
   * Gets item from database via condition
   * @param {string} collection - item id
   * @param {Object} condition - item id
   *   * @param {string} select - fields to select
   * @param {string} population - population string
  */

  async getItemCustom(collection, condition, select = '', population = '') {
    return new Promise(async (resolve, reject) => {
      try {
        const item = await collection.findOne(condition).select(select).populate(population).sort({
          createdAt: -1
        });
        resolve({
          success: true,
          data: item
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },

  async deleteCustom(collection, condition) {
    return new Promise((resolve, reject) => {
      collection.deleteOne(condition, function (err) {
        resolve(buildSuccObject("DELETED"));
      })
    });
  },






  async  getItemsCustomWithBookingTime(model, model2, whereObj, populateFields, sort, limit, offset) {
    // Perform your main query to fetch users or artists based on the given criteria (whereObj).
    const results = await model.find(whereObj)
      .populate(populateFields)
      .sort(sort)
      .skip(offset)
      .limit(limit);
  
    // Now, for each result (user or artist), fetch the booking time from the booking table.
    for (const result of results) {
      // Assuming you have a booking model and appropriate relationships defined in your schema.
      const booking = await model2.findOne({ _id: result.booking_id ,  }); // Adjust this query as per your schema.
      if (booking) {
        result.bookingTime = booking.bookingTime; // Add booking time to the result object.
      }
    }
  
    return results;
  },
  /**
   * Gets items from database with population, sort
   * @param {string} collection - collection name
   * @param {Object} condition - condition
   * @param {string} select - fields to select
   * @param {string} population - population string
   * @param {Object} sort - sort object
   * @param {Number} limit - records to fetch
   * @param {Number} offset - records to skip
  */

  async getItemsCustom(collection, condition, select = '', population = '', sort = {}, limit = Number.MAX_SAFE_INTEGER, offset = 0) {
    return new Promise(async (resolve, reject) => {
      try {
        const record = await collection.find(condition).select(select).populate(population).sort(sort).skip(+offset).limit(+limit);
        resolve({
          success: true,
          data: record
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },






  /**
   * Gets items from database with population, sort
   * @param {string} collection - collection name
   * @param {Object} condition - condition
   * @param {string} select - fields to select
   * @param {string} population - population string
   * @param {Object} sort - sort object
   * @param {Number} limit - records to fetch
   * @param {Number} offset - records to skip
  */

  async getItemsCustomforSelect(collection, condition, select = '', select1 = '', population = '', sort = {}, limit = Number.MAX_SAFE_INTEGER, offset = 0) {
    return new Promise(async (resolve, reject) => {
      try {
        const record = await collection.find(condition).select(select).populate({ path: population, select: select1 }).sort(sort).skip(+offset).limit(+limit);
        resolve({
          success: true,
          data: record
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },

  /**
   * Gets count of documents from collection
   * @param {string} collection - collection name
   * @param {Object} condition - condition
  */

  async getItemsCustomforPopulate(collection, condition, select = '', select1 = '', population = '' , population2 = '', sort = {}, limit = Number.MAX_SAFE_INTEGER, offset = 0) {
    console.log('condition--->>>',condition)
    return new Promise(async (resolve, reject) => {
      try {
        const record = await collection.find(condition).select(select).sort(sort).populate(population).populate({ 
          path: population2, 
          populate: { 
            path: select1 ,
            match: condition,
          } 
        }).skip(+offset).limit(+limit);
        resolve({
          success: true,
          data: record
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },



  // 
  async countDocuments(collection, condition) {
    return new Promise(async (resolve, reject) => {
      try {
        const count = await collection.countDocuments(condition);
        resolve(count);
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },

  async locations(collection, data) {
    return new Promise(async (resolve, reject) => {
      try {
        const response = await collection.aggregate([
          {
            $geoNear: {
              near: {
                type: "Point",
                coordinates: [Number(data.long), Number(data.lat)],
              },
              distanceField: "distance",
              spherical: true,
              distanceMultiplier: 0.001,
            },
          },
          {
            $lookup: {
              from: "postmedias",
              localField: "_id",
              foreignField: "post_id",
              as: "media",
            },
          },
          { $skip: +data.offset },
          { $limit: +data.limit },
        ])
        resolve(response);
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },


  async locationswithusers(collection, data) {
    return new Promise(async (resolve, reject) => {
      try {
        const response = await collection.aggregate([
          {
            $geoNear: {
              near: {
                type: "Point",
                coordinates: [Number(data.long), Number(data.lat)],
              },
              distanceField: "distance",
              spherical: true,
              distanceMultiplier: 0.001,
            },
          },
          {
            $lookup: {
              from: "postmedias",
              localField: "_id",
              foreignField: "post_id",
              as: "media",
            },
          },
          {
            $lookup: {
              from: "users",
              localField: "user_id",
              foreignField: "_id",
              as: "users",
            },
          },
          {
            $unwind: {
              path: '$users',
              preserveNullAndEmptyArrays: true,
            },
          },
          /* {
            "$project": {
              "_id": 0,
              "user_data.stage_name": 1,
              "user_data.artist_profile_image": 1
            }
          }, */
          { $skip: +data.offset },
          { $limit: +data.limit },
        ])
        resolve(response);
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },
  /**
   * Aggregate collection
   * @param {string} collection - collection name
   * @param {Array} condition - condition
  */

  async aggregateCollection(collection, condition) {
    return new Promise(async (resolve, reject) => {
      try {

        const record = await collection.aggregate(condition);

        resolve({
          success: true,
          data: record
        });
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }
    });
  },

  async objectId(idString) {
    return new Promise(async (resolve, reject) => {
      try {
        const objectId = mongoose.Types.ObjectId(idString);
        resolve(objectId);
      } catch (error) {
        reject(buildErrObject(422, error.message));
      }

    })
  },

  sendNotification: sendNotification,


};