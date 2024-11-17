import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
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
      await deleteTokensByUserId(userId, req.cookies.token);
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

export const changePassword = async (req, res) => {
  const userId = req.userId;
  const { currentPassword, newPassword } = req.body;

  try {
    const user = await User.findById(userId);

    if (!(await user.comparePassword(currentPassword))) {
      logger.error('Invalid credentials', {
        method: req.method,
        url: req.originalUrl,
        userId: userId,
      });
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    user.password = newPassword;
    await user.save();

    await deleteTokensByUserId(userId, req.cookies.token);

    logger.info('Password changed successfully', {
      method: req.method,
      url: req.originalUrl,
      userId: userId,
    });

    res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    logger.error('Error when authenticating', {
      method: req.method,
      url: req.originalUrl,
      error: error,
    });
    res.status(500).json({ message: 'Error when authenticating' });
  }
};

export const deleteUser = async (req, res) => {
  const userId = req.params.id;

  try {
    await User.findByIdAndDelete(userId);

    await deleteTokensByUserId(userId, req.cookies.token);

    logger.info('User deleted successfully', {
      method: req.method,
      url: req.originalUrl,
      user: userId,
      userId: req.userId,
      ip: req.ip,
    });
    res.status(204).send();
  } catch (error) {
    logger.error('Error deleting user', {
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
      if (user.totpSecret) {
        const sessionKey = `2fa_pending:${user._id.toString()}:${
          (req.headers && req.headers['x-forwarded-for']) || req.ip
        }`;

        redisClient.set(
          sessionKey,
          true,
          'EX',
          parseInt(process.env.TOTP_EXPIRATION) || 300
        );

        logger.info('2FA session started', {
          method: req.method,
          url: req.originalUrl,
          userId: user._id.toString(),
        });

        // We return a 200 status code to indicate that the user must now verify the 2FA token
        return res.status(200).json({
          message: 'Credentials validated, please verify 2FA token',
          userId: user._id.toString(),
        });
      }

      // If the user does not have 2FA enabled, we generate the tokens and send them to the user
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
      redisClient.set(
        authToken,
        user._id.toString(),
        'EX',
        parseInt(process.env.JWT_EXPIRATION) || 3600
      );
      redisClient.set(
        refreshToken,
        user._id.toString(),
        'EX',
        parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600
      );

      // We create an index to be able to search by userId
      redisClient.sadd(`user_tokens:${user._id.toString()}`, authToken);
      redisClient.sadd(`user_tokens:${user._id.toString()}`, refreshToken);

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
  }
};

export const enable2FA = async (req, res) => {
  try {
    const user = await User.findById(req.userId);

    const secret = speakeasy.generateSecret({ name: 'CloudMedix' });

    user.totpSecret = secret.base32;
    await user.save();

    qrcode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
      if (err) {
        logger.error('Error generating QR code', {
          method: req.method,
          url: req.originalUrl,
          error: err,
          userId: req.userId,
        });
        return res.status(500).json({ message: 'Internal server error' });
      }

      return res
        .status(200)
        .json({ message: '2FA enabled successfully', qrCodeUrl });
    });
  } catch (error) {
    logger.error('Error enabling 2FA', {
      method: req.method,
      url: req.originalUrl,
      error: error.message,
      userId: req.userId,
    });
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const verify2FA = async (req, res) => {
  const { userId, totpToken } = req.body;

  try {
    const sessionKey = `2fa_pending:${userId}:${
      (req.headers && req.headers['x-forwarded-for']) || req.ip
    }`;

    const sessionExists = await redisClient.exists(sessionKey);
    if (!sessionExists) {
      return res
        .status(403)
        .json({ message: '2FA session expired or invalid' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.totpSecret) {
      return res.status(403).json({ message: '2FA not enabled for this user' });
    }

    const isTokenValid = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: 'base32',
      token: totpToken,
      window: 1,
    });

    if (!isTokenValid) {
      return res.status(400).json({ message: 'Invalid 2FA token' });
    }

    await redisClient.del(sessionKey);

    // If the totpToken is valid, we generate the jwt tokens
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

    redisClient.set(
      authToken,
      user._id.toString(),
      'EX',
      parseInt(process.env.JWT_EXPIRATION) || 3600
    );
    redisClient.set(
      refreshToken,
      user._id.toString(),
      'EX',
      parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600
    );

    redisClient.sadd(`user_tokens:${user._id.toString()}`, authToken);
    redisClient.sadd(`user_tokens:${user._id.toString()}`, refreshToken);

    res.cookie('token', authToken, { httpOnly: true });
    res.cookie('refreshToken', refreshToken, { httpOnly: true });

    logger.info(`User logged in with 2FA: "${user.email}"`, {
      method: req.method,
      url: req.originalUrl,
      userId: user._id.toString(),
    });

    return res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    logger.error('Error logging in with 2FA', {
      method: req.method,
      url: req.originalUrl,
      userId,
      error: error.message,
    });

    return res.status(500).json({ message: 'Internal server error' });
  }
};
