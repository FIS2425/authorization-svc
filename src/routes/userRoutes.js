import express from 'express';
import { getUser, createUser, login, logout } from '../controllers/userController.js';
import { validateToken, validate } from '../middleware/validationMiddleware.js';
import { checkRoles, userExists, hasAccessToUser } from '../middleware/authMiddleware.js';
import {
  userValidator,
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

router.post('/login', validate(userLoginValidator), login);

router.post('/logout', logout);

router.get('/users/:id', validateToken, userExists, hasAccessToUser, getUser);

export default router;
