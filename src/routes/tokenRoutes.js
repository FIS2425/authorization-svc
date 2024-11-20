import express from 'express';
import { validate, refresh } from '../controllers/tokenController.js';
import { validateAuthToken, validateRefreshToken } from '../middleware/validationMiddleware.js';

const router = express.Router();

router.get('/validate', validateAuthToken, validate);
router.get('/refresh', validateRefreshToken, refresh);

export default router;
