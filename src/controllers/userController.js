import User from '../schemas/User.js';
import jwt from 'jsonwebtoken';
import redisClient from '../config/index.js';

export const register = async (req, res) => { };

export const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (await user.comparePassword(password)) {
      const authToken = await jwt.sign(
        {
          userId: user._id.toString(),
          roles: user.roles,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_EXPIRATION || 3600,
        },
      );
      const refreshToken = await jwt.sign(
        {
          userId: user._id.toString(),
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d',
        },
      );

      // We save the token to the cache, so that in cases of emergy we can revoke it
      redisClient.set(authToken, user._id.toString(), { EX: parseInt(process.env.JWT_EXPIRATION) || 3600 });
      redisClient.set(refreshToken, user._id.toString(), { EX: parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600 });

      res.cookie('token', authToken, { httpOnly: true });
      res.cookie('refreshToken', refreshToken, { httpOnly: true });

      res.status(200).json({ message: 'Login successful' });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.log(error);
    res.status(401).json({ message: 'Invalid credentials' });
  }
};

export const logout = async (req, res) => {
  res.clearCookie('token');
  res.clearCookie('refreshToken');

  const authToken = req.cookies.token;

  if (!authToken) {
    res.status(401).json({ message: 'Not logged in' });
  } else {
    try {
      redisClient.del(authToken);
      res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      // Here token has probably expired. To the user it's the same as if it was deleted
      console.log(error);
      res.status(200).json({ message: 'Logout successful' });
    }
  }
};
