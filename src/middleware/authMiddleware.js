import logger from '../config/logger.js';
import User from '../schemas/User.js';
import Role from '../schemas/Role.js';

export const checkRoles = (...roles) => {
  return async (req, res, next) => {
    if (!roles.every((role) => req.roles.includes(role))) {
      logger.warn('Forbidden', {
        method: req.method,
        url: req.originalUrl,
        userId: req.userId,
        ip: req.ip,
      });
      return res.status(403).json({ message: 'Forbidden' });
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
  const hasAccess =
    req.roles.includes('admin') ||
    req.roles.includes('clinicadmin') ||
    req.roles.includes('doctor') ||
    req.params.id === req.userId.toString();
  if (!hasAccess) {
    logger.warn('Forbidden', {
      method: req.method,
      url: req.originalUrl,
      userId: req.userId,
      ip: req.ip,
    });
    return res.status(403).json({ message: 'Forbidden' });
  }
  next();
};

// Middleware to authorize requests based on user roles and permissions
export const authorizeRequest = (method) => {
  return async (req, res, next) => {
    try {
      const userRoles = req.roles;

      const validMethods = [
        'get',
        'create',
        'edit',
        'delete',
        'changePassword',
      ];
      if (!validMethods.includes(method)) {
        logger.error('Invalid method', {
          method: req.method,
          url: req.originalUrl,
          userId: req.userId,
          ip: req.ip,
        });
        return res.status(400).json({ message: 'Invalid method' });
      }

      if (!userRoles || userRoles.length === 0) {
        logger.warn('Forbidden', {
          method: req.method,
          url: req.originalUrl,
          userId: req.userId,
          ip: req.ip,
        });
        return res.status(403).json({ message: 'Forbidden' });
      }

      const rolesData = await Role.find({ role: { $in: userRoles } });

      let hasPermission = false;

      if (method === 'create') {
        // Check for roles in the new user data for 'create' method
        const newUserRoles = req.body.roles || [];
        hasPermission = rolesData.some((role) => {
          return role.permissions.some(
            (permission) =>
              permission.method === 'create' &&
              newUserRoles.every((role) => permission.onRoles.includes(role))
          );
        });
      } else {
        // Check permissions for other methods (get, edit, delete, changePassword)
        hasPermission = rolesData.some((role) => {
          return role.permissions.some(
            (permission) =>
              permission.method === method &&
              permission.onRoles.includes('himself')
          );
        });

        const targetUserId = req.params.id;
        const targetUser = await User.findById(targetUserId);
        const targetUserRoles = targetUser ? targetUser.roles : [];

        // If the target user is not the same as the current user, check permissions
        if (targetUserId && targetUserId !== req.userId) {
          hasPermission = rolesData.some((role) => {
            return role.permissions.some(
              (permission) =>
                permission.method === method &&
                targetUserRoles.every((role) =>
                  permission.onRoles.includes(role)
                )
            );
          });
        }

        // Additional check for 'edit' method to ensure the user has permissions to assign roles
        if (method === 'edit' && req.body.roles) {
          const newRoles = req.body.roles;
          const canAssignRoles = rolesData.some((role) => {
            return role.permissions.some(
              (permission) =>
                permission.method === 'edit' &&
                newRoles.every((role) => permission.onRoles.includes(role))
            );
          });

          if (!canAssignRoles) {
            logger.warn('Forbidden', {
              method: req.method,
              url: req.originalUrl,
              userId: req.userId,
              ip: req.ip,
            });
            return res.status(403).json({ message: 'Forbidden' });
          }
        }
      }

      if (!hasPermission) {
        logger.warn('Forbidden', {
          method: req.method,
          url: req.originalUrl,
          userId: req.userId,
          ip: req.ip,
        });
        return res.status(403).json({ message: 'Forbidden' });
      }

      next();
    } catch (error) {
      logger.error('Server error', {
        method: req.method,
        url: req.originalUrl,
        userId: req.userId,
        ip: req.ip,
        error: error.message,
      });
      res.status(500).json({ message: 'Server error' });
    }
  };
};
