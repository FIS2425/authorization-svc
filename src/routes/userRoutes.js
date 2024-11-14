import express from 'express';
import {
  createUser,
  getUser,
  editUser,
  changePassword,
  deleteUser,
  login,
  logout,
} from '../controllers/userController.js';
import { validateToken, validate } from '../middleware/validationMiddleware.js';
import { userExists, authorizeRequest } from '../middleware/authMiddleware.js';
import {
  userValidator,
  userEditValidator,
  userLoginValidator,
  changePasswordValidator,
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

export default router;
