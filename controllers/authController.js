const User = require('../models/User');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();
// Configuración de Google OAuth
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `http://localhost:${process.env.PORT || 3000}/api/auth/google/callback`
    },
    async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
        });
      }
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));
} else {
  console.warn('Credenciales de Google OAuth no configuradas. La autenticación de Google no estará disponible.');
}

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

exports.signup = async (req, res) => {
  console.log('JWT_SECRET:', process.env.JWT_SECRET);
    try {
      const newUser = await User.create({
        email: req.body.email,
        password: req.body.password,
      });
  
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
        expiresIn: '1d',
      });
  
      res.status(201).json({
        status: 'success',
        token,
        data: {
          user: newUser,
        },
      });
    } catch (error) {
      res.status(400).json({
        status: 'fail',
        message: error.message,
      });
    }
  };

exports.login = async (req, res) => {

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Por favor proporcione email y contraseña',
      });
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Email o contraseña incorrectos',
      });
    }

    // Si el usuario tiene 2FA habilitado, no inicie sesión aún
    if (user.twoFactorSecret) {
      return res.status(200).json({
        status: 'success',
        message: 'Por favor, proporcione el código 2FA',
        requiresTwoFactor: true,
      });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.status(200).json({
      status: 'success',
      token,
    });
  } catch (error) {
    res.status(400).json({
      status: 'fail',
      message: error.message,
    });
  }
};

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};

exports.generateTwoFactor = async (req, res) => {
  console.log('Generando 2FA para el usuario:', req.user);
  try {
    const secret = speakeasy.generateSecret({ length: 32 });
    console.log('Secret generado:', secret);
    const user = await User.findById(req.user._id);
    console.log('Usuario encontrado:', user);
    user.twoFactorSecret = secret.base32;
    await user.save();
    console.log('Usuario actualizado con 2FA secret');

    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret.ascii,
      label: 'SecureLoginApp',
      issuer: 'YourCompany',
    });

    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);
    console.log('QR code generado');

    res.status(200).json({
      status: 'success',
      data: {
        qrCodeDataUrl,
      },
    });
  } catch (error) {
    console.error('Error en generateTwoFactor:', error);
    res.status(400).json({
      status: 'fail',
      message: error.message,
    });
  }
};

exports.verifyTwoFactor = async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id);

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
    });

    if (!verified) {
      return res.status(400).json({
        status: 'fail',
        message: 'Código 2FA inválido',
      });
    }

    const jwtToken = jwt.sign({ id: user._id }, 'tu_secreto_jwt', {
      expiresIn: '1d',
    });

    res.status(200).json({
      status: 'success',
      token: jwtToken,
    });
  } catch (error) {
    res.status(400).json({
      status: 'fail',
      message: error.message,
    });
  }
};

exports.googleAuth = passport.authenticate('google', { scope: ['profile', 'email'] });

exports.googleAuthCallback = (req, res, next) => {
  passport.authenticate('google', { session: false }, (err, user) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.redirect('/login');
    }
    const token = jwt.sign({ id: user._id }, 'tu_secreto_jwt', {
      expiresIn: '1d',
    });
    res.cookie('jwt', token, {
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });
    res.redirect('/dashboard');
  })(req, res, next);
};

exports.getCsrfToken = (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
  };