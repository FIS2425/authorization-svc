import logger from '../config/logger.js';
import User from '../schemas/User.js';

export const checkRole = (role) => {
  return async (req, res, next) => {
    const user = await User.findById(req.userId);
    if (!user.roles.includes(role)) {
      logger.warn('Unauthorized', {
        method: req.method,
        url: req.originalUrl,
        userId: req.userId,
        ip: req.ip,
      });
      return res.status(403).json({ message: 'Unauthorized' });
    }
    next();
  };
};
