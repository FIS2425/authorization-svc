import express from 'express';
import { validate } from '../controllers/validationController.js';
import { validateAuthToken } from '../middleware/validationMiddleware.js';

const router = express.Router();

router.get('/validate', validateAuthToken, validate);

export default router;
