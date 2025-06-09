const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error('MONGO_URI 環境變數未設定');
    }

    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB 連線成功');
  } catch (err) {
    console.error('MongoDB 連線失敗:', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;
