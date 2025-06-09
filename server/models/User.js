const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, '請輸入姓名'],
      trim: true,
    },
    email: {
      type: String,
      required: [true, '請輸入電子郵件'],
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, '請輸入密碼'],
      minlength: [8, '密碼長度至少為8個字元'],
      select: false,
    },
    role: {
      type: String,
      enum: ['訪客', '一般使用者', '管理者'],
      default: '一般使用者',
    },
    workArea: {
      type: String,
      enum: ['', '雙北桃竹苗', '中彰投', '雲嘉南', '高高屏'],
      default: '',
    },
    identityId: {
      type: String,
      trim: true,
    },
    birthday: {
      type: Date,
    },
    phone: {
      type: String,
      trim: true,
    },
    mobile: {
      type: String,
      trim: true,
    },
    address: {
      city: String,
      district: String,
      village: String,
      neighborhood: String,
      street: String,
      section: String,
      lane: String,
      alley: String,
      number: String,
      floor: String,
    },
    identityType: {
      type: String,
      enum: ['', '公', '私'],
      default: '',
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    lastLoginAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

// 密碼加密
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// 驗證密碼
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// 生成 JWT token
userSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
};

// 生成重設密碼令牌
userSchema.methods.getResetPasswordToken = function () {
  // 生成令牌
  const resetToken = crypto.randomBytes(20).toString('hex');

  // 哈希令牌並設置到 resetPasswordToken 欄位
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // 設置過期時間（10分鐘）
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
