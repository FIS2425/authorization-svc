import User from '../schemas/User.js';
import jwt from 'jsonwebtoken';
import { redisClient } from '../config/redis.js';

import logger from '../config/logger.js';

export const createUser = async (req, res) => {
  try {
    const { email, password, roles, doctorid, patientid } = req.body;

    const errors = {};

    if (!email) {
      errors.email = 'Email is required';
    }

    if (!password) {
      errors.password = 'Password is required';
    }

    if (Object.keys(errors).length > 0) {
      logger.warn('Missing required fields', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        errors,
      });
      return res.status(400).json(errors);
    }

    const existingUserEmail = await User.findOne({ email });

    if (existingUserEmail) {
      logger.warn('User already exists', {
        method: req.method,
        url: req.originalUrl,
        email,
        ip: req.ip,
      });
      return res.status(400).json({
        message: 'A user with that email already exists.',
      });
    }

    const newUser = new User({
      email,
      password,
      roles,
      doctorid,
      patientid,
    });

    await newUser.save();

    // eslint-disable-next-line no-unused-vars
    const { password: _, ...userWithoutPassword } = newUser.toObject(); // Remove password from the user object to be returned

    logger.info('User created successfully', {
      method: req.method,
      url: req.originalUrl,
      email: newUser.email,
      userId: newUser._id.toString(),
      ip: req.ip,
    });

    res.status(201).json(userWithoutPassword);
  } catch (error) {
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map((err) => err.message);

      logger.error('Validation error creating user', {
        method: req.method,
        url: req.originalUrl,
        error: errors,
        ip: req.ip,
      });

      return res.status(400).json({ messages: errors });
    }
    logger.error('Error creating user', {
      method: req.method,
      url: req.originalUrl,
      error: error.message,
      ip: req.ip,
    });
    res.status(500).json({
      message: 'Internal server error.',
    });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({ message: 'User not found' });
    } else if (await user.comparePassword(password)) {
      const authToken = await jwt.sign(
        {
          userId: user._id.toString(),
          roles: user.roles,
        },
        process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
        {
          expiresIn: parseInt(process.env.JWT_EXPIRATION) || 3600,
        },
      );
      const refreshToken = await jwt.sign(
        {
          userId: user._id.toString(),
        },
        process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
        {
          expiresIn: parseInt(process.env.JWT_REFRESH_EXPIRATION) || '7d',
        },
      );

      // We save the token to the cache, so that in cases of emergy we can revoke it
      redisClient.set(authToken, user._id.toString(), {
        EX: parseInt(process.env.JWT_EXPIRATION) || 3600,
      });
      redisClient.set(refreshToken, user._id.toString(), {
        EX: parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600,
      });

      res.cookie('token', authToken, { httpOnly: true });
      res.cookie('refreshToken', refreshToken, { httpOnly: true });

      logger.info(`User logged in: "${user.email}"`, {
        method: req.method,
        url: req.originalUrl,
        userId: user._id.toString(),
      });
      res.status(200).json({ message: 'Login successful' });
    } else {
      logger.error('Invalid credentials', {
        method: req.method,
        url: req.originalUrl,
        userId: user._id.toString(),
      });
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    logger.error('Error when authenticating', {
      method: req.method,
      url: req.originalUrl,
      error: error,
    });
    res.status(500).json({ message: 'Error when authenticating' });
  }
};

export const logout = async (req, res) => {
  res.clearCookie('token');
  res.clearCookie('refreshToken');

  const authToken = req.cookies.token;

  if (!authToken) {
    res.status(401).json({ message: 'Not logged in' });
  } else {
    const decoded = jwt.verify(
      authToken,
      process.env.JWT_SECRET || process.env.VITE_JWT_SECRET
    );
    const userId = decoded.userId;
    try {
      logger.info('User logged out ${ user.email }', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
      });
      redisClient.del(authToken);
      logger.info('Token revoked', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
      });

      res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      // Here token has probably expired. To the user it's the same as if it was deleted
      logger.info('Token expired', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
      });
      res.status(200).json({ message: 'Logout successful' });
    }
  }
};
