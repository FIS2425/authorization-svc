import logger from '../utils/logger';

export const validate = async (req, res) => {
  // At this point the token has been validated by the middleware
  logger.info('Validated user identity', {
    method: req.method,
    url: req.originalUrl,
    userId: req.userId,
    ip: req.ip,
  });
  res.status(200).json({ message: 'Token is valid' });
};
