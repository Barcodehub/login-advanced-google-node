const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');

const app = express();

// Conexión a MongoDB
mongoose.connect('mongodb://localhost:27017/secureLoginApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware
app.use(express.json({ limit: '10kb' })); // Limita el tamaño del body
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Configuración de seguridad
app.use(helmet()); // Cabeceras HTTP seguras
app.use(xss()); // Sanitización contra XSS
app.use(mongoSanitize()); // Prevención de inyección NoSQL

// Rate limiting
const limiter = rateLimit({
  max: 100, // Máximo 100 solicitudes
  windowMs: 60 * 60 * 1000, // 1 hora
  message: 'Demasiadas solicitudes desde esta IP, por favor intente de nuevo en una hora.',
});
app.use('/api', limiter);

// Configuración de sesiones
app.use(session({
  secret: 'tu_secreto_super_seguro',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/secureLoginApp' }),
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Usar HTTPS en producción
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 semana
  },
}));

// Inicialización de Passport
app.use(passport.initialize());
app.use(passport.session());

// CSRF protection
app.use(csrf({ cookie: true }));

// Rutas
const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));