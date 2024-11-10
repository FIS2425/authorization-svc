import logger from '../config/logger.js';
import User from '../schemas/User.js';

export const checkRoles = (...roles) => {
  return async (req, res, next) => {
    if (!roles.every((role) => req.roles.includes(role))) {
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

export const userExists = async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    logger.warn('User not found', {
      method: req.method,
      url: req.originalUrl,
      userId: req.userId,
      ip: req.ip,
    });
    return res.status(404).json({ message: 'User not found' });
  }
  req.onUser = user;
  next();
};

export const hasAccessToUser = async (req, res, next) => {
  const hasAccess = req.roles.includes('admin') ||
        req.roles.includes('clinicadmin') ||
        req.roles.includes('doctor') ||
        req.params.id === req.userId.toString();
  if (!hasAccess) {
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
