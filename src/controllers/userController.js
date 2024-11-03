import User from '../schemas/User.js';
import AuthToken from '../schemas/AuthToken.js';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => { };

export const login = async (req, res) => {
  const { name, password } = req.body;

  try {
    const user = await User.findOne({ name });
    if (await user.comparePassword(password)) {
      const authToken = await jwt.sign({
        userId: user._id.toString(),
        roles: user.roles,
      }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRATION || '1h',
      });
      const refreshToken = await jwt.sign({
        userId: user._id.toString(),
      }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d',
      });

      // We save the token to the database, so that in cases of emergy we can revoke it
      await new AuthToken({
        token: authToken,
        userId: user,
        roles: user.roles,
      }).save();

      res.cookie('token', authToken, { httpOnly: true });
      res.cookie('refreshToken', refreshToken, { httpOnly: true });

      res.status(200).json({ message: 'Login successful' });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (_) {
    res.status(401).json({ message: 'Invalid credentials' });
  }
};

export const logout = async (req, res) => { };
