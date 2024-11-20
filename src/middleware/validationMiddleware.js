import jwt from 'jsonwebtoken';
import { redisClient, deleteToken } from '../config/redis.js';
import logger from '../config/logger.js';
import User from '../schemas/User.js';

const validateToken = async (token, req, res) => {
  const user = await User.findById(req.userId);

  if (!user) {
    logger.warn('User not found', {
      requestId: req.headers && req.headers['x-request-id'] || null,
      ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
      method: req.method,
      url: req.originalUrl,
      userId: req.userId,
    });
    return res.status(401).json({ message: 'User not found' });
  }

  const tokenValid = await redisClient.exists(token);

  if (!tokenValid) {
    logger.warn('Token expired', {
      requestId: req.headers && req.headers['x-request-id'] || null,
      ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
      method: req.method,
      url: req.originalUrl,
    });
    await deleteToken(req.userId, token);
    return res.status(401).json({ message: 'Token expired' });
  }

  return true;
};

export const validateRefreshToken = async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_SECRET || process.env.VITE_JWT_SECRET
    );
    req.userId = decoded.userId;
    req.roles = decoded.roles;

    const isTokenValid = await validateToken(refreshToken, req, res);

    if (typeof isTokenValid === 'boolean' && isTokenValid) {
      next();
    }
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.error('Error on token validation', {
        request_id: req.headers && req.headers['x-request-id'] || '',
        method: req.method,
        url: req.originalUrl,
        error: error,
      });
      return res.status(401).json({ message: 'Token expired' });
    } else {
      logger.error('Error on token validation', {
        request_id: req.headers && req.headers['x-request-id'] || '',
        method: req.method,
        url: req.originalUrl,
        error: error,
      });
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
};

export const validateAuthToken = async (req, res, next) => {
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
    req.roles = decoded.roles;

    const isTokenValid = await validateToken(token, req, res);

    if (typeof isTokenValid === 'boolean' && isTokenValid) {
      next();
    }
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.error('Error on token validation', {
        requestId: req.headers && req.headers['x-request-id'] || null,
        ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
        method: req.method,
        url: req.originalUrl,
        error: error,
      });
      return res.status(401).json({ message: 'Token expired' });
    } else {
      logger.error('Error on token validation', {
        requestId: req.headers && req.headers['x-request-id'] || null,
        ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
        method: req.method,
        url: req.originalUrl,
        error: error,
      });
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
};

export const validate = (validator) => async (req, res, next) => {
  try {
    await validator.parseAsync(req.body);
    next();
  } catch (error) {
    logger.error('Error on validation', {
      method: req.method,
      url: req.originalUrl,
      error: error.errors,
      ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
      requestId: req.headers && req.headers['x-request-id'] || null,
    });

    const formattedErrors = error.errors.reduce((acc, err) => {
      const field = err.path[0];
      acc[field] = err.message;
      return acc;
    }, {});

    return res.status(400).json({
      message: 'Validation error',
      errors: formattedErrors,
    });
  }
};
