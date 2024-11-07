import express from 'express';
import { validate } from '../controllers/validationController.js';
import { validateToken } from '../middleware/validationMiddleware.js';

const router = express.Router();

router.get('/validate', validateToken, validate);

export default router;
