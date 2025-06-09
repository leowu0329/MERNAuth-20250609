const express = require('express');
const router = express.Router();
const {
  register,
  login,
  logout,
  forgotPassword,
  resetPassword,
  getMe,
  updateProfile,
  updatePassword,
} = require('../controllers/authController');
const auth = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.post('/forgot-password', forgotPassword);
router.put('/reset-password/:token', resetPassword);
router.get('/me', auth, getMe);
router.put('/profile', auth, updateProfile);
router.put('/update-password', auth, updatePassword);

module.exports = router;
