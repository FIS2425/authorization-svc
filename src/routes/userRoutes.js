import express from 'express';
import { createUser, login, logout } from '../controllers/userController.js';
import { validateToken } from '../middleware/validationMiddleware.js';
import { checkRoles } from '../middleware/authMiddleware.js';

const router = express.Router();

router.post('/users', validateToken, checkRoles('clinicadmin'), createUser);

router.post('/login', login);

router.post('/logout', logout);

export default router;
