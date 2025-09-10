import User from '../models/User.js';

const sendTokenResponse = (user, statusCode, res) => {
  const token = user.generateAuthToken();
  const options = { 
    expires: new Date(
      Date.now() + (parseInt(process.env.JWT_COOKIE_EXPIRE) || 7) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.status(statusCode)
    .cookie('token', token, options)
    .json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        avatar: user.avatar,
        preferences: user.preferences,
        lastLogin: user.lastLogin
      }
    });
};



// @desc    Insert user
// @route   POST /api/auth/register
// @access  Public
export const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Please provide name, email, password.'
      });
    }
    
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
    //const verificationToken = user.generateEmailVerificationToken();
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
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user (with password)
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      console.log(`Login attempt with non-existent email: ${email}`, {
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });

      // Increase brute force count
      if (req.incrementLoginAttempts) {
        req.incrementLoginAttempts();
      }

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      console.log(`Login attempt on locked account: ${email}`, {
        userId: user._id,
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });

      return res.status(423).json({
        success: false,
        error: 'Account temporarily locked. Try again later.'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      console.log(`Login attempt on inactive account: ${email}`, {
        userId: user._id,
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });

      return res.status(401).json({
        success: false,
        error: 'Account is deactivated'
      });
    }

    // Check if password is correct
    const isPasswordCorrect = await user.comparePassword(password);

    if (!isPasswordCorrect) {
      console.log(`Failed login attempt: ${email}`, {
        userId: user._id,
        ip: req.clientIP,
        userAgent: req.headers['user-agent']
      });

      // Save failed login attempt
      await user.incLoginAttempts();

      // Increase brute force count
      if (req.incrementLoginAttempts) {
        req.incrementLoginAttempts();
      }

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // Successful login
    await user.resetLoginAttempts();
    await user.updateLastLogin(req.clientIP);

    // Reset brute force count
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
      error: 'Server Error'
    });
  }
};

// @desc    Get current user info
// @route   GET /api/auth/me
// @access  Private
export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        avatar: user.avatar,
        phone: user.phone,
        dateOfBirth: user.dateOfBirth,
        address: user.address,
        preferences: user.preferences,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    });
  } catch (error) {
    console.log('Get me error:', error);
    res.status(500).json({
      success: false,
      error: 'Server Error'
    });
  }
};


// @desc    User Logout
// @route   POST /api/auth/logout
// @access  Private
export const logout = (req, res) => {
  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  console.log(`User logged out: ${req.user.email}`, {
    userId: req.user._id,
    ip: req.clientIP
  });

  res.status(200).json({
    success: true,
    message: 'Başarıyla çıkış yapıldı'
  });
};