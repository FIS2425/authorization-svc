import logger from '../config/logger.js';
import User from '../schemas/User.js';
import Role from '../schemas/Role.js';

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
      let canAssignRoles = true;

      // Check permissions for accessing endpoint
      hasPermission = rolesData.some((role) => {
        return role.permissions.some(
          (permission) =>
            permission.method === method
        );
      });

      if (req.params && req.params.id) {
        const targetUserId = req.params.id;
        const targetUser = await User.findById(targetUserId);
        const targetUserRoles = targetUser ? targetUser.roles : [];

        // If the target user is not the same as the current user, check permissions on current method
        if (targetUserId && targetUserId !== req.userId) {
          hasPermission = hasPermission &&
                        rolesData.some((role) => {
                          return role.permissions.some(
                            (permission) =>
                              permission.method === method &&
                                    targetUserRoles.every((onRole) =>
                                      permission.onRoles.includes(onRole)
                                    )
                          );
                        });
        } else {
          hasPermission = hasPermission &&
                        rolesData.some((role) => {
                          return role.permissions.some(
                            (permission) =>
                              permission.method === method &&
                                    permission.onRoles.includes('himself')
                          );
                        });
        };
      };
      // Additional check for 'edit' method to ensure the user has permissions to assign roles
      if (method === 'create' || method === 'edit' && req.body.roles) {
        const newRoles = req.body.roles;
        canAssignRoles = rolesData.some((role) => {
          return role.permissions.some(
            (permission) =>
              permission.method === method &&
                            newRoles.every((newrole) => permission.onRoles.includes(newrole))
          );
        });
      }

      if (!hasPermission || !canAssignRoles) {
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
      logger.error('Internal server error', {
        method: req.method,
        url: req.originalUrl,
        userId: req.userId,
        ip: req.ip,
        error: error.message,
      });
      res.status(500).json({ message: 'Internal server error' });
    }
  };
};
