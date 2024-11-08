import jwt from 'jsonwebtoken';
import { redisClient } from '../config/redis.js';
import logger from '../config/logger.js';
import User from '../schemas/User.js';

export const validateToken = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || process.env.VITE_JWT_SECRET
    );
    req.userId = decoded.userId;

    const user = await User.findById(req.userId);

    if (!user) {
      logger.warn('User not found', {
        method: req.method,
        url: req.originalUrl,
        userId: req.userId,
        ip: req.ip,
      });
      return res.status(401).json({ message: 'User not found' });
    }

    const tokenValid = await redisClient.exists(token);

    if (!tokenValid) {
      logger.warn('Token expired', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
      });
      return res.status(401).json({ message: 'Token expired' });
    }

    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.error('Error on token validation', {
        method: req.method,
        url: req.originalUrl,
        error: error,
      });
      return res.status(401).json({ message: 'Token expired' });
    } else {
      logger.error('Error on token validation', {
        method: req.method,
        url: req.originalUrl,
        error: error,
      });
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
};
