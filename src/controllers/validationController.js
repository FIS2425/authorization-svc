import logger from '../config/logger.js';

export const validate = async (req, res) => {
  // At this point the token has been validated by the middleware
  logger.info('Validated user identity', {
    method: req.method,
    url: req.originalUrl,
    userId: req.userId,
    ip: req.headers && req.headers['x-forwarded-for'] || req.ip,
    requestId: req.headers && req.headers['x-request-id'] || null,
  });
  res.status(200).json({ message: 'Token is valid' });
};
