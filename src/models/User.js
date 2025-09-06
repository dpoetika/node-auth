import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'İsim gereklidir'],
    trim: true,
    minlength: [2, 'İsim en az 2 karakter olmalıdır'],
    maxlength: [50, 'İsim en fazla 50 karakter olabilir'],
    match: [/^[a-zA-ZğüşıöçĞÜŞİÖÇ0-9\s]+$/, 'İsim sadece harf, rakam ve boşluk içerebilir']
  },
  email: {
    type: String,
    required: [true, 'Email gereklidir'],
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: [100, 'Email en fazla 100 karakter olabilir'],
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Geçerli bir email adresi giriniz']
  },
  password: {
    type: String,
    required: [true, 'Şifre gereklidir'],
    minlength: [8, 'Şifre en az 8 karakter olmalıdır'],
    maxlength: [128, 'Şifre en fazla 128 karakter olabilir'],
    select: false // Varsayılan olarak şifreyi döndürme
  },
  role: {
    type: String,
    enum: {
      values: ['user', 'admin', 'moderator'],
      message: 'Rol user, admin veya moderator olmalıdır'
    },
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  avatar: {
    type: String,
    default: null
  },
  phone: {
    type: String,
    trim: true,
    match: [/^[0-9+\-\s()]+$/, 'Geçerli bir telefon numarası giriniz']
  },
  dateOfBirth: {
    type: Date,
    validate: {
      validator: function(value) {
        return !value || value < new Date();
      },
      message: 'Doğum tarihi gelecekte olamaz'
    }
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  preferences: {
    language: {
      type: String,
      enum: ['tr', 'en'],
      default: 'tr'
    },
    theme: {
      type: String,
      enum: ['light', 'dark'],
      default: 'light'
    },
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    }
  },
  // Güvenlik alanları
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  lastLogin: Date,
  lastLoginIP: String,
  twoFactorSecret: String,
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  // Metadata
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});


export default mongoose.model('User', userSchema);