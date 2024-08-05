const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Por favor proporcione un email'],
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: [true, 'Por favor proporcione una contraseña'],
    minlength: 8,
    select: false,
  },
  twoFactorSecret: String,
  googleId: String,
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

module.exports = mongoose.model('User', userSchema);