const User = require('../models/User');

// @desc    Insert user
// @route   POST /api/auth/register
// @access  Public
const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user exist
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'This email is in using'
      });
    }

    // Create new user
    const user = await User.create({
      name,
      email,
      password,
      role: role || 'user'
    });

    // Email verification token created
    const verificationToken = user.generateEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    console.log(`New user registered: ${email}`, {
      userId: user._id,
      ip: req.clientIP,
      userAgent: req.headers['user-agent']
    });

    // TODO: Send an email to verify email
    // await sendVerificationEmail(user.email, verificationToken);

    sendTokenResponse(user, 201, res);
  } catch (error) {
    console.log('Registration error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        error: 'Bu email adresi zaten kullanılıyor'
      });
    }

    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(val => val.message);
      return res.status(400).json({
        success: false,
        error: 'Geçersiz veri',
        details: messages
      });
    }

    res.status(500).json({
      success: false,
      error: 'Sunucu hatası'
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Kullanıcıyı bul (şifre ile birlikte)
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      console.log(`Login attempt with non-existent email: ${email}`, {
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });
      
      // Brute force sayacını artır
      if (req.incrementLoginAttempts) {
        req.incrementLoginAttempts();
      }
      
      return res.status(401).json({
        success: false,
        error: 'Geçersiz email veya şifre'
      });
    }

    // Hesap kilitli mi kontrol et
    if (user.isLocked) {
      console.log(`Login attempt on locked account: ${email}`, {
        userId: user._id,
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });
      
      return res.status(423).json({
        success: false,
        error: 'Hesap geçici olarak kilitlenmiştir. Lütfen daha sonra tekrar deneyin.'
      });
    }

    // Hesap aktif mi kontrol et
    if (!user.isActive) {
      console.log(`Login attempt on inactive account: ${email}`, {
        userId: user._id,
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });
      
      return res.status(401).json({
        success: false,
        error: 'Hesabınız deaktif edilmiştir'
      });
    }

    // Şifre doğru mu kontrol et
    const isPasswordCorrect = await user.comparePassword(password);

    if (!isPasswordCorrect) {
      console.log(`Failed login attempt: ${email}`, {
        userId: user._id,
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });

      // Başarısız giriş denemesini kaydet
      await user.incLoginAttempts();
      
      // Brute force sayacını artır
      if (req.incrementLoginAttempts) {
        req.incrementLoginAttempts();
      }
      
      return res.status(401).json({
        success: false,
        error: 'Geçersiz email veya şifre'
      });
    }

    // Başarılı giriş
    await user.resetLoginAttempts();
    await user.updateLastLogin(req.clientIP);
    
    // Brute force sayacını sıfırla
    if (req.resetLoginAttempts) {
      req.resetLoginAttempts();
    }

    console.log(`Successful login: ${email}`, {
      userId: user._id,
      ip: req.clientIP,
      userAgent: req.headers['user-agent']
    });

    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.log('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Sunucu hatası'
    });
  }
};


export default {register,login};