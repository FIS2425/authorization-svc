import User from '../schemas/User.js';
import jwt from 'jsonwebtoken';
import { redisClient } from '../config/redis.js';

import logger from '../config/logger.js';

export const register = async (req, res) => { };

export const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
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
      redisClient.set(authToken, user._id.toString(), { EX: parseInt(process.env.JWT_EXPIRATION) || 3600 });
      redisClient.set(refreshToken, user._id.toString(), { EX: parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600 });

      res.cookie('token', authToken, { httpOnly: true });
      res.cookie('refreshToken', refreshToken, { httpOnly: true });

      logger.info(`User logged in: "${user.username}"`, {
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
    const decoded = jwt.verify(authToken, process.env.JWT_SECRET || process.env.VITE_JWT_SECRET);
    const userId = decoded.userId;
    try {
      logger.info('User logged out ${ user.username }', {
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
