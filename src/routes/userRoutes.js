import express from 'express';
import { createUser, login, logout } from '../controllers/userController.js';
import { validateToken, validate } from '../middleware/validationMiddleware.js';
import { checkRoles } from '../middleware/authMiddleware.js';
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

export default router;
