import express from 'express';
import {
  createUser,
  getUser,
  editUser,
  changePassword,
  deleteUser,
  login,
  logout,
  enable2FA,
  verify2FA,
} from '../controllers/userController.js';
import { validateToken, validate } from '../middleware/validationMiddleware.js';
import { userExists, authorizeRequest } from '../middleware/authMiddleware.js';
import {
  userValidator,
  userEditValidator,
  userLoginValidator,
  changePasswordValidator,
  verify2FAValidator,
} from '../validators/userValidator.js';

const router = express.Router();

router.post(
  '/users',
  validateToken,
  validate(userValidator),
  authorizeRequest('create'),
  createUser
);

router.get(
  '/users/:id',
  validateToken,
  userExists,
  authorizeRequest('get'),
  getUser
);

router.put(
  '/users/:id',
  validateToken,
  userExists,
  validate(userEditValidator),
  authorizeRequest('edit'),
  editUser
);

router.delete(
  '/users/:id',
  validateToken,
  userExists,
  authorizeRequest('delete'),
  deleteUser
);

router.post(
  '/users/change-password',
  validateToken,
  validate(changePasswordValidator),
  authorizeRequest('changePassword'),
  changePassword
);

router.post('/login', validate(userLoginValidator), login);

router.post('/logout', logout);

router.post('/users/enable-2fa', validateToken, enable2FA);

router.post('/users/verify-2fa', validate(verify2FAValidator), verify2FA);

export default router;
