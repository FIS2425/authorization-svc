import express from 'express';
import { getUser, createUser, login, logout } from '../controllers/userController.js';
import { validateToken } from '../middleware/validationMiddleware.js';
import { checkRoles, userExists, hasAccessToUser } from '../middleware/authMiddleware.js';

const router = express.Router();

router.post('/users', validateToken, checkRoles('clinicadmin'), createUser);

router.post('/login', login);

router.post('/logout', logout);

router.get('/users/:id', validateToken, userExists, hasAccessToUser, getUser);

export default router;
