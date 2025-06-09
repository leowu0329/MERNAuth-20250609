const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: '請填寫所有欄位' });
    }
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: '此信箱已註冊' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });
    const token = generateToken(user._id);
    res.status(201).json({
      message: '註冊成功',
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ message: '伺服器錯誤' });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 檢查是否提供電子郵件和密碼
    if (!email || !password) {
      return res.status(400).json({
        message: '請提供電子郵件和密碼',
      });
    }

    // 查找用戶
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        message: '電子郵件或密碼錯誤',
      });
    }

    // 驗證密碼
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        message: '電子郵件或密碼錯誤',
      });
    }

    // 更新最後登入時間
    user.lastLoginAt = new Date();
    await user.save();

    // 生成 JWT token
    const token = generateToken(user._id);

    // 返回用戶資料（不包含密碼）
    const userResponse = user.toObject();
    delete userResponse.password;

    res.json({
      token,
      user: userResponse,
    });
  } catch (error) {
    console.error('登入錯誤:', error);
    res.status(500).json({
      message: '登入失敗',
    });
  }
};

exports.logout = (req, res) => {
  res.json({ message: '登出成功' });
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // 驗證輸入
    if (!email) {
      return res.status(400).json({ message: '請輸入信箱' });
    }

    // 查找用戶
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: '查無此信箱' });
    }

    // 生成重設令牌
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpire = Date.now() + 1000 * 60 * 30; // 30分鐘

    try {
      // 更新用戶資料
      const updateResult = await User.updateOne(
        { _id: user._id },
        {
          $set: {
            resetToken,
            resetTokenExpire,
          },
        },
      );

      if (updateResult.modifiedCount === 0) {
        throw new Error('更新用戶資料失敗');
      }

      // 生成重設連結
      const resetUrl = `${
        process.env.CLIENT_URL || 'http://localhost:5173'
      }/reset-password/${resetToken}`;

      // 發送郵件
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: '重設密碼請求',
        html: `
          <div style="font-family: 'Noto Sans TC', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #0d6efd; text-align: center;">重設密碼請求</h2>
            <p>親愛的 ${user.name}：</p>
            <p>我們收到了您的密碼重設請求。請點擊下面的連結來重設您的密碼：</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" 
                 style="background-color: #0d6efd; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                重設密碼
              </a>
            </div>
            <p>此連結將在 30 分鐘後失效。</p>
            <p>如果您沒有請求重設密碼，請忽略此郵件。</p>
            <hr style="border: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px; text-align: center;">
              此郵件由系統自動發送，請勿回覆。
            </p>
          </div>
        `,
      };

      await transporter.sendMail(mailOptions);

      res.json({
        message: '重設密碼連結已寄出，請檢查您的信箱',
      });
    } catch (saveError) {
      console.error('更新用戶資料或發送郵件失敗:', saveError);
      return res.status(500).json({
        message: '發送重設密碼郵件失敗，請稍後再試',
        error:
          process.env.NODE_ENV === 'development'
            ? saveError.message
            : undefined,
      });
    }
  } catch (err) {
    console.error('忘記密碼錯誤:', err);
    res.status(500).json({
      message: '伺服器錯誤，請稍後再試',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    // 驗證輸入
    if (!token || !password) {
      return res.status(400).json({ message: '缺少必要資訊' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: '密碼長度至少為 6 個字元' });
    }

    let user;

    // 檢查是否是從導航列直接訪問（使用郵箱）
    if (token.includes('@')) {
      user = await User.findOne({ email: token });
      if (!user) {
        return res.status(404).json({ message: '找不到該用戶' });
      }
    } else {
      // 使用重設令牌查找用戶
      user = await User.findOne({
        resetToken: token,
        resetTokenExpire: { $gt: Date.now() },
      });
      if (!user) {
        return res.status(400).json({ message: '重設連結無效或已過期' });
      }
    }

    try {
      // 更新用戶密碼
      const hashedPassword = await bcrypt.hash(password, 10);
      const updateResult = await User.updateOne(
        { _id: user._id },
        {
          $set: {
            password: hashedPassword,
            resetToken: null,
            resetTokenExpire: null,
          },
        },
      );

      if (updateResult.modifiedCount === 0) {
        throw new Error('更新密碼失敗');
      }

      res.json({ message: '密碼重設成功' });
    } catch (updateError) {
      console.error('更新密碼失敗:', updateError);
      return res.status(500).json({
        message: '更新密碼失敗，請稍後再試',
        error:
          process.env.NODE_ENV === 'development'
            ? updateError.message
            : undefined,
      });
    }
  } catch (err) {
    console.error('重設密碼錯誤:', err);
    res.status(500).json({
      message: '伺服器錯誤，請稍後再試',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }
};

exports.getProfile = async (req, res) => {
  res.json({ user: req.user });
};

exports.updateProfile = async (req, res) => {
  try {
    const {
      name,
      email,
      role,
      workArea,
      identityId,
      birthday,
      phone,
      mobile,
      address,
      identityType,
    } = req.body;
    const userId = req.user.id;

    console.log('更新資料請求:', {
      userId,
      name,
      email,
      role,
      workArea,
      identityId,
      birthday,
      phone,
      mobile,
      address,
      identityType,
    });

    // 驗證必要欄位
    if (!name || !email) {
      return res.status(400).json({ message: '請填寫所有必要欄位' });
    }

    // 檢查郵箱是否已被其他用戶使用
    const existingUser = await User.findOne({
      email,
      _id: { $ne: userId },
    });

    if (existingUser) {
      return res.status(400).json({ message: '此郵箱已被使用' });
    }

    try {
      // 準備更新資料
      const updateData = {
        name,
        email,
        role,
        workArea,
        identityId,
        birthday: birthday ? new Date(birthday) : null,
        phone,
        mobile,
        address,
        identityType,
      };

      console.log('準備更新的資料:', updateData);

      // 更新用戶資料
      const updateResult = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true, runValidators: true },
      ).select('-password -resetToken -resetTokenExpire');

      if (!updateResult) {
        throw new Error('找不到用戶');
      }

      console.log('更新成功:', updateResult);

      res.json({
        message: '個人資料更新成功',
        user: updateResult,
      });
    } catch (updateError) {
      console.error('更新資料失敗:', updateError);
      return res.status(500).json({
        message: '更新資料失敗，請稍後再試',
        error:
          process.env.NODE_ENV === 'development'
            ? updateError.message
            : undefined,
      });
    }
  } catch (err) {
    console.error('更新個人資料錯誤:', err);
    res.status(500).json({
      message: '伺服器錯誤，請稍後再試',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }
};
