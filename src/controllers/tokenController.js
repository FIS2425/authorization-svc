import logger from '../config/logger.js';
import { redisClient } from '../config/redis.js';
import jwt from 'jsonwebtoken';
import User from '../schemas/User.js';

export const validate = async (req, res) => {
  // At this point the token has been validated by the middleware
  logger.info('Validated user identity', {
    request_id: req.headers && req.headers['x-request-id'] || '',
    method: req.method,
    url: req.originalUrl,
    userId: req.userId,
    ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
  });
  res.status(200).json({ message: 'Token is valid' });
};

export const refresh = async (req, res) => {
  // At this point the token has been validated by the middleware
  const oldToken = req.cookies.token;
  const oldRefreshToken = req.cookies.refreshToken;

  try {
    const user = await User.findById(req.userId);

    redisClient.exists(oldToken) && redisClient.del(oldToken);
    redisClient.exists(oldRefreshToken) && redisClient.del(oldRefreshToken);

    redisClient.smismember(`user_tokens:${user._id.toString()}`, oldToken) &&
            redisClient.srem(`user_tokens:${user._id.toString()}`, oldToken);

    redisClient.smismember(`user_tokens:${user._id.toString()}`, oldRefreshToken) &&
            redisClient.srem(`user_tokens:${user._id.toString()}`, oldRefreshToken);

    const token_expiration = parseInt(process.env.JWT_EXPIRATION) || 3600;
    const refreshToken_expiration = parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600;

    const authToken = await jwt.sign(
      {
        userId: user._id.toString(),
        roles: user.roles,
      },
      process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
      {
        expiresIn: token_expiration,
      }
    );

    const refreshToken = await jwt.sign(
      {
        userId: user._id.toString(),
      },
      process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
      {
        expiresIn: refreshToken_expiration,
      }
    );

    redisClient.set(
      authToken,
      user._id.toString(),
      'EX',
      parseInt(process.env.JWT_EXPIRATION) || 3600
    );
    redisClient.set(
      refreshToken,
      user._id.toString(),
      'EX',
      parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600
    );

    redisClient.sadd(`user_tokens:${user._id.toString()}`, authToken);
    redisClient.sadd(`user_tokens:${user._id.toString()}`, refreshToken);

    res.cookie('token', authToken, { httpOnly: true, maxAge: token_expiration * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: refreshToken_expiration * 1000 });

    logger.info(`Tokens refreshed: "${user.email}"`, {
      request_id: req.headers && req.headers['x-request-id'] || '',
      method: req.method,
      url: req.originalUrl,
      userId: user._id.toString(),
    });

    return res.status(200).json({ message: 'Tokens refhresed' });
  } catch (error) {
    logger.error('Error refreshing tokens', {
      request_id: req.headers && req.headers['x-request-id'] || '',
      method: req.method,
      url: req.originalUrl,
      userId: req.userId,
      error: error.message,
    });

    return res.status(500).json({ message: 'Internal server error' });
  }
};
