import logger from '../config/logger.js';
import { redisClient } from '../config/redis.js';
import { generateTokens } from '../utils/generateTokens.js';
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

    await generateTokens(user, res);

    logger.info(`Tokens refreshed: "${user.email}"`, {
      request_id: req.headers && req.headers['x-request-id'] || '',
      method: req.method,
      url: req.originalUrl,
      userId: user._id.toString(),
    });

    return res.status(200).json({ message: 'Tokens refreshed' });
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
