const mongoose = require('mongoose')

module.exports = () => {

  const connect = async () => {
    try {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('MongoDB connected successfully');
    } catch (error) {
      console.error('Error connecting to MongoDB:', error.message);
    }
  };

  connect()

  mongoose.connection.on('error', console.log)
  mongoose.connection.on('disconnected', connect)
}