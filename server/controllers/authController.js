const User = require('../models/User');
const asyncHandler = require('../middleware/async');
const ErrorResponse = require('../utils/errorResponse');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// 生成 JWT token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
};

// 創建郵件傳輸器
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// @desc    註冊用戶
// @route   POST /api/auth/register
// @access  Public
exports.register = asyncHandler(async (req, res, next) => {
  const { name, email, password } = req.body;

  console.log('註冊請求:', { name, email });

  // 檢查必要欄位
  if (!name || !email || !password) {
    console.log('缺少必要欄位:', {
      name: !!name,
      email: !!email,
      password: !!password,
    });
    return next(new ErrorResponse('請填寫所有必要欄位', 400));
  }

  // 檢查電子郵件格式
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.log('電子郵件格式不正確:', email);
    return next(new ErrorResponse('請輸入有效的電子郵件地址', 400));
  }

  // 檢查密碼長度
  if (password.length < 8) {
    console.log('密碼長度不足:', password.length);
    return next(new ErrorResponse('密碼長度至少為8個字元', 400));
  }

  try {
    // 檢查是否已存在相同 email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('電子郵件已被註冊:', email);
      return next(new ErrorResponse('此電子郵件已被註冊', 400));
    }

    // 創建用戶
    const user = await User.create({
      name,
      email,
      password,
    });

    console.log('用戶創建成功:', { id: user._id, email: user.email });

    // 生成 token
    const token = user.getSignedJwtToken();

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('註冊錯誤:', error);
    // 處理 Mongoose 驗證錯誤
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map((err) => err.message);
      return next(new ErrorResponse(messages.join(', '), 400));
    }
    // 處理重複電子郵件錯誤
    if (error.code === 11000 && error.keyPattern?.email) {
      return next(new ErrorResponse('此電子郵件已被註冊', 400));
    }
    return next(new ErrorResponse('註冊失敗，請稍後再試', 500));
  }
});

// @desc    登入用戶
// @route   POST /api/auth/login
// @access  Public
exports.login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  console.log('登入請求:', { email });

  // 驗證 email & password
  if (!email || !password) {
    console.log('缺少必要欄位:', { email: !!email, password: !!password });
    return next(new ErrorResponse('請提供 email 和密碼', 400));
  }

  // 檢查用戶
  const user = await User.findOne({ email }).select('+password');
  console.log('查找用戶結果:', user ? '找到用戶' : '未找到用戶');

  if (!user) {
    return next(new ErrorResponse('輸入的帳號及密碼錯誤', 401));
  }

  // 檢查密碼是否匹配
  const isMatch = await user.matchPassword(password);
  console.log('密碼匹配結果:', isMatch ? '密碼正確' : '密碼錯誤');

  if (!isMatch) {
    return next(new ErrorResponse('輸入的帳號及密碼錯誤', 401));
  }

  // 更新最後登入時間
  user.lastLoginAt = Date.now();
  await user.save();
  console.log('更新最後登入時間成功');

  // 生成 token
  const token = user.getSignedJwtToken();
  console.log('生成 token 成功');

  res.status(200).json({
    success: true,
    token,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      workArea: user.workArea,
      identityId: user.identityId,
      birthday: user.birthday,
      phone: user.phone,
      mobile: user.mobile,
      address: user.address,
      identityType: user.identityType,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      lastLoginAt: user.lastLoginAt,
    },
  });
});

// @desc    獲取當前用戶
// @route   GET /api/auth/me
// @access  Private
exports.getMe = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc    忘記密碼
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  console.log('忘記密碼請求:', { email });

  if (!email) {
    console.log('缺少電子郵件地址');
    return next(new ErrorResponse('請提供電子郵件地址', 400));
  }

  const user = await User.findOne({ email });
  console.log('查找用戶結果:', user ? '找到用戶' : '未找到用戶');

  if (!user) {
    return next(new ErrorResponse('找不到該電子郵件的用戶', 404));
  }

  try {
    // 生成重置令牌
    const resetToken = user.getResetPasswordToken();
    console.log('生成重設令牌:', {
      resetToken,
      hashedToken: user.resetPasswordToken,
      expireTime: new Date(user.resetPasswordExpire).toISOString(),
    });

    await user.save({ validateBeforeSave: false });
    console.log('保存用戶資料成功');

    // 檢查環境變數
    console.log('環境變數檢查:', {
      FRONTEND_URL: process.env.FRONTEND_URL,
      EMAIL_USER: process.env.EMAIL_USER ? '已設置' : '未設置',
      EMAIL_PASS: process.env.EMAIL_PASS ? '已設置' : '未設置',
    });

    if (!process.env.FRONTEND_URL) {
      throw new Error('FRONTEND_URL 環境變數未設置');
    }

    // 創建重設密碼的 URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    console.log('重設密碼 URL:', resetUrl);

    // 檢查郵件傳輸器配置
    if (!transporter) {
      throw new Error('郵件傳輸器未正確配置');
    }

    // 發送重設密碼郵件
    const message = `
      您收到此郵件是因為您（或其他人）請求重設密碼。
      請點擊以下連結重設密碼：
      ${resetUrl}
      
      此連結將在 10 分鐘後失效。
      
      如果您沒有請求重設密碼，請忽略此郵件。
    `;

    console.log('準備發送郵件:', {
      to: user.email,
      subject: '密碼重設請求',
      messageLength: message.length,
    });

    const mailOptions = {
      to: user.email,
      subject: '密碼重設請求',
      text: message,
    };

    await transporter.sendMail(mailOptions);
    console.log('重設密碼郵件發送成功');

    res.status(200).json({
      success: true,
      message: '密碼重設郵件已發送',
      resetUrl: resetUrl, // 在開發環境中返回 URL 以便測試
    });
  } catch (error) {
    console.error('發送重設密碼郵件錯誤:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
    });

    // 清理用戶的重設令牌
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new ErrorResponse(`無法發送重設密碼郵件: ${error.message}`, 500),
    );
  }
});

// @desc    重置密碼
// @route   PUT /api/auth/reset-password/:token
// @access  Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { password } = req.body;
  const { token } = req.params;
  console.log('重設密碼請求:', {
    token,
    passwordLength: password?.length,
  });

  if (!password) {
    console.log('缺少新密碼');
    return next(new ErrorResponse('請提供新密碼', 400));
  }

  if (password.length < 8) {
    console.log('密碼長度不足:', password.length);
    return next(new ErrorResponse('密碼長度至少為8個字元', 400));
  }

  try {
    // 獲取哈希的令牌
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    console.log('哈希後的令牌:', resetPasswordToken);

    // 查找用戶，並檢查令牌是否過期
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    console.log('查找用戶結果:', {
      found: !!user,
      tokenMatch: !!user?.resetPasswordToken,
      tokenExpired: user ? Date.now() > user.resetPasswordExpire : null,
      currentTime: new Date().toISOString(),
      expireTime: user?.resetPasswordExpire
        ? new Date(user.resetPasswordExpire).toISOString()
        : null,
    });

    if (!user) {
      console.log('無效或已過期的令牌');
      return next(new ErrorResponse('無效或已過期的重設密碼令牌', 400));
    }

    // 設置新密碼
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    console.log('密碼重設成功');

    // 生成新的 JWT token
    const newToken = user.getSignedJwtToken();
    console.log('生成新的 JWT token');

    res.status(200).json({
      success: true,
      message: '密碼重設成功',
      token: newToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        workArea: user.workArea,
        identityId: user.identityId,
        birthday: user.birthday,
        phone: user.phone,
        mobile: user.mobile,
        address: user.address,
        identityType: user.identityType,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        lastLoginAt: user.lastLoginAt,
      },
    });
  } catch (error) {
    console.error('重設密碼錯誤:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
    });
    return next(new ErrorResponse('重設密碼失敗，請稍後再試', 500));
  }
});

// @desc    更新用戶資料
// @route   PUT /api/auth/profile
// @access  Private
exports.updateProfile = asyncHandler(async (req, res, next) => {
  const fieldsToUpdate = {
    name: req.body.name,
    email: req.body.email,
    role: req.body.role,
    workArea: req.body.workArea,
    identityId: req.body.identityId,
    birthday: req.body.birthday,
    phone: req.body.phone,
    mobile: req.body.mobile,
    address: req.body.address,
    identityType: req.body.identityType,
  };

  // 移除未定義的欄位
  Object.keys(fieldsToUpdate).forEach((key) => {
    if (fieldsToUpdate[key] === undefined) {
      delete fieldsToUpdate[key];
    }
  });

  // 確保 workArea 是有效的值
  if (
    fieldsToUpdate.workArea &&
    !['', '雙北桃竹苗', '中彰投', '雲嘉南', '高高屏'].includes(
      fieldsToUpdate.workArea,
    )
  ) {
    return next(new ErrorResponse('無效的工作轄區', 400));
  }

  const user = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
    new: true,
    runValidators: true,
  });

  if (!user) {
    return next(new ErrorResponse('找不到用戶', 404));
  }

  res.status(200).json({
    success: true,
    message: '資料更新成功',
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      workArea: user.workArea,
      identityId: user.identityId,
      birthday: user.birthday,
      phone: user.phone,
      mobile: user.mobile,
      address: user.address,
      identityType: user.identityType,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      lastLoginAt: user.lastLoginAt,
    },
  });
});

// @desc    更新密碼
// @route   PUT /api/auth/update-password
// @access  Private
exports.updatePassword = asyncHandler(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  // 驗證輸入
  if (!currentPassword || !newPassword) {
    return next(new ErrorResponse('請提供當前密碼和新密碼', 400));
  }

  // 驗證新密碼
  if (newPassword.length < 8) {
    return next(new ErrorResponse('新密碼必須至少包含8個字元', 400));
  }

  if (/^\d+$/.test(newPassword)) {
    return next(new ErrorResponse('密碼不能完全是數字', 400));
  }

  // 獲取用戶
  const user = await User.findById(req.user.id).select('+password');

  // 驗證當前密碼
  const isMatch = await user.matchPassword(currentPassword);
  if (!isMatch) {
    return next(new ErrorResponse('當前密碼不正確', 401));
  }

  // 更新密碼
  user.password = newPassword;
  await user.save();

  sendTokenResponse(user, 200, res);
});

// 獲取 token 並創建 cookie
const sendTokenResponse = (user, statusCode, res) => {
  // 創建 token
  const token = user.getSignedJwtToken();

  const options = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000,
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') {
    options.secure = true;
  }

  res.status(statusCode).json({
    success: true,
    token,
  });
};

exports.logout = (req, res) => {
  res.json({ message: '登出成功' });
};
