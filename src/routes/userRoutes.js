import express from 'express';
import {
  createUser,
  getUser,
  editUser,
  deleteUser,
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
  // CheckRoles must be changed for the planned permissions feature
  checkRoles('clinicadmin'),
  validate(userValidator),
  createUser
);

router.get('/users/:id', validateToken, userExists, hasAccessToUser, getUser);

router.put(
  '/users/:id',
  validateToken,
  userExists,
  // hasAccessToUser must be changed for the planned permissions feature
  hasAccessToUser,
  validate(userEditValidator),
  editUser
);

router.delete(
  '/users/:id',
  validateToken,
  userExists,
  // hasAccessToUser must be changed for the planned permissions feature. A patient should not be able to delete itself.
  hasAccessToUser,
  validate(userEditValidator),
  deleteUser
);

router.post('/login', validate(userLoginValidator), login);

router.post('/logout', logout);

export default router;
