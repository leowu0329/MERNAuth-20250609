const express = require('express');
const cors = require('cors');
require('dotenv').config();
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const ErrorResponse = require('./utils/errorResponse');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

connectDB();

app.get('/', (req, res) => {
  res.send('伺服器運作中');
});

app.use('/api/auth', authRoutes);

// 錯誤處理中間件
app.use((err, req, res, next) => {
  console.error('錯誤:', err);

  let error = { ...err };
  error.message = err.message;

  // Mongoose 重複鍵錯誤
  if (err.code === 11000) {
    const message = '此電子郵件已被註冊';
    error = new ErrorResponse(message, 400);
  }

  // Mongoose 驗證錯誤
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map((val) => val.message);
    error = new ErrorResponse(message, 400);
  }

  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || '伺服器錯誤',
  });
});

app.listen(PORT, () => {
  console.log(`伺服器啟動於 http://localhost:${PORT}`);
});
