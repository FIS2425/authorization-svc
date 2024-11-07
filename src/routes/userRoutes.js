import express from 'express';
import { createUser, login, logout } from '../controllers/userController.js';

const router = express.Router();

router.post('/users', createUser);

router.post('/login', login);

router.post('/logout', logout);

export default router;
