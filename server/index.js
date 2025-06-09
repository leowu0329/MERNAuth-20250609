const express = require('express');
const cors = require('cors');
require('dotenv').config();
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

connectDB();

app.get('/', (req, res) => {
  res.send('伺服器運作中');
});

app.use('/api/auth', authRoutes);

app.listen(PORT, () => {
  console.log(`伺服器啟動於 http://localhost:${PORT}`);
});
