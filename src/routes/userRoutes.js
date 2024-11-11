import express from 'express';
import {
  createUser,
  getUser,
  editUser,
  login,
  logout,
} from '../controllers/userController.js';
import { validateToken, validate } from '../middleware/validationMiddleware.js';
import { userExists, authorizeRequest } from '../middleware/authMiddleware.js';
import {
  userValidator,
  userEditValidator,
  userLoginValidator,
} from '../validators/userValidator.js';

const router = express.Router();

router.post(
  '/users',
  validateToken,
  authorizeRequest('create'),
  validate(userValidator),
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
  authorizeRequest('edit'),
  validate(userEditValidator),
  editUser
);

router.post('/login', validate(userLoginValidator), login);

router.post('/logout', logout);

export default router;
