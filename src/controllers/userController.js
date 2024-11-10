import jwt from 'jsonwebtoken';
import User from '../schemas/User.js';
import logger from '../config/logger.js';
import { redisClient, deleteTokensByUserId } from '../config/redis.js';

export const createUser = async (req, res) => {
  try {
    const { email, password, roles, doctorid, patientid } = req.body;

    const existingUserEmail = await User.findOne({ email });

    if (existingUserEmail) {
      logger.warn('User already exists', {
        method: req.method,
        url: req.originalUrl,
        email,
        ip: req.ip,
      });
      return res.status(400).json({
        message: 'A user with that email already exists.',
      });
    }

    const newUser = new User({
      email,
      password,
      roles,
      doctorid,
      patientid,
    });

    await newUser.save();

    // eslint-disable-next-line no-unused-vars
    const { password: _, ...userWithoutPassword } = newUser.toObject(); // Remove password from the user object to be returned

    logger.info('User created successfully', {
      method: req.method,
      url: req.originalUrl,
      email: newUser.email,
      userId: newUser._id.toString(),
      ip: req.ip,
    });

    res.status(201).json(userWithoutPassword);
  } catch (error) {
    logger.error('Error creating user', {
      method: req.method,
      url: req.originalUrl,
      error: error.message,
      ip: req.ip,
    });
    res.status(500).json({
      message: 'Internal server error.',
    });
  }
};

export const getUser = async (req, res) => {
  const userId = req.params.id;

  try {
    const user = await User.findById(userId);

    // eslint-disable-next-line no-unused-vars
    const { password, ...userWithoutPassword } = user.toObject();
    logger.info('User retrieved successfully', {
      method: req.method,
      url: req.originalUrl,
      user: userId,
      userId: req.userId,
      ip: req.ip,
    });
    res.status(200).json(userWithoutPassword);
  } catch (error) {
    logger.error('Error retrieving user', {
      method: req.method,
      url: req.originalUrl,
      error: error.message,
      user: userId,
      userId: req.userId,
      ip: req.ip,
    });
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const editUser = async (req, res) => {
  const userId = req.params.id;

  try {
    const user = await User.findById(userId);

    const { email, password, roles } = req.body;

    const existingUserEmail = await User.findOne({ email });

    if (existingUserEmail && existingUserEmail._id.toString() !== userId) {
      logger.warn('User already exists', {
        method: req.method,
        url: req.originalUrl,
        email,
        ip: req.ip,
      });
      return res.status(400).json({
        message: 'A user with that email already exists.',
      });
    }

    email && (user.email = email);
    password && (user.password = password);
    roles && (user.roles = roles);

    if (password || roles) {
      deleteTokensByUserId(userId, null);
    }

    await user.save();

    // eslint-disable-next-line no-unused-vars
    const { password: _, ...userWithoutPassword } = user.toObject();
    logger.info('User updated successfully', {
      method: req.method,
      url: req.originalUrl,
      user: userId,
      userId: req.userId,
      ip: req.ip,
    });
    res.status(200).json(userWithoutPassword);
  } catch (error) {
    logger.error('Error updating user', {
      method: req.method,
      url: req.originalUrl,
      error: error.message,
      user: userId,
      userId: req.userId,
      ip: req.ip,
    });
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({ message: 'User not found' });
    } else if (await user.comparePassword(password)) {
      const authToken = await jwt.sign(
        {
          userId: user._id.toString(),
          roles: user.roles,
        },
        process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
        {
          expiresIn: parseInt(process.env.JWT_EXPIRATION) || 3600,
        }
      );
      const refreshToken = await jwt.sign(
        {
          userId: user._id.toString(),
        },
        process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
        {
          expiresIn: parseInt(process.env.JWT_REFRESH_EXPIRATION) || '7d',
        }
      );

      // We save the token to the cache, so that in cases of emergy we can revoke it
      redisClient.set(authToken, user._id.toString(), {
        EX: parseInt(process.env.JWT_EXPIRATION) || 3600,
      });
      redisClient.set(refreshToken, user._id.toString(), {
        EX: parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600,
      });

      // We create an index to be able to search by userId
      redisClient.sAdd(`user_tokens:${user._id.toString()}`, authToken);
      redisClient.sAdd(`user_tokens:${user._id.toString()}`, refreshToken);

      res.cookie('token', authToken, { httpOnly: true });
      res.cookie('refreshToken', refreshToken, { httpOnly: true });

      logger.info(`User logged in: "${user.email}"`, {
        method: req.method,
        url: req.originalUrl,
        userId: user._id.toString(),
      });
      res.status(200).json({ message: 'Login successful' });
    } else {
      logger.error('Invalid credentials', {
        method: req.method,
        url: req.originalUrl,
        userId: user._id.toString(),
      });
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    logger.error('Error when authenticating', {
      method: req.method,
      url: req.originalUrl,
      error: error,
    });
    res.status(500).json({ message: 'Error when authenticating' });
  }
};

export const logout = async (req, res) => {
  res.clearCookie('token');
  res.clearCookie('refreshToken');

  const authToken = req.cookies.token;

  if (!authToken) {
    res.status(401).json({ message: 'Not logged in' });
  } else {
    const decoded = jwt.verify(
      authToken,
      process.env.JWT_SECRET || process.env.VITE_JWT_SECRET
    );
    const userId = decoded.userId;
    try {
      logger.info('User logged out ${ user.email }', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
      });
      redisClient.del(authToken);
      logger.info('Token revoked', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
      });

      res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      // Here token has probably expired. To the user it's the same as if it was deleted
      logger.info('Token expired', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
        error: error,
      });
      res.status(200).json({ message: 'Logout successful' });
    }
  };
};
