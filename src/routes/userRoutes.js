import express from 'express';
import {
  createUser,
  getUser,
  editUser,
  login,
  logout,
} from '../controllers/userController.js';
import { validateToken, validate } from '../middleware/validationMiddleware.js';
import {
  checkRoles,
  userExists,
  hasAccessToUser,
} from '../middleware/authMiddleware.js';
import {
  userValidator,
  userEditValidator,
  userLoginValidator,
} from '../validators/userValidator.js';

const router = express.Router();

router.post(
  '/users',
  validateToken,
  checkRoles('clinicadmin'),
  validate(userValidator),
  createUser
);

router.get('/users/:id', validateToken, userExists, hasAccessToUser, getUser);

router.put(
  '/users/:id',
  validateToken,
  userExists,
  hasAccessToUser,
  validate(userEditValidator),
  editUser
);

router.post('/login', validate(userLoginValidator), login);

router.post('/logout', logout);

export default router;
