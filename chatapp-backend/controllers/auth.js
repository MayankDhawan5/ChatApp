const Joi = require('joi');
const http = require('http');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../models/userModels');
const Helpers = require('../Helpers/helpers');
const dbConfig = require('../config/secret');

module.exports = {
  async CreateUser(req, res) {
    const schema = Joi.object().keys({
      username: Joi.string().min(5).max(10).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(5).required(),
    });

    try {
      const { error, value } = await schema.validateAsync(req.body);
      if (error && error.details) {
        return res
          .status(http.StatusCodes.BAD_REQUEST)
          .json({ msg: error.details });
      }

      const userEmail = await User.findOne({
        email: Helpers.lowerCase(req.body.email),
      });
      if (userEmail) {
        return res
          .status(http.StatusCodes.CONFLICT)
          .json({ message: 'Email already exists' });
      }

      const userName = await User.findOne({
        username: Helpers.firstUpper(req.body.username),
      });
      if (userName) {
        return res
          .status(http.StatusCodes.CONFLICT)
          .json({ message: 'Username already exists' });
      }

      const hash = await bcrypt.hash(value.password, 10);
      const body = {
        username: Helpers.firstUpper(value.username),
        email: Helpers.lowerCase(value.email),
        password: hash,
      };

      const user = await User.create(body);
      const token = jwt.sign({ data: user }, dbConfig.secret, {
        expiresIn: '5h',
      });

      res.cookie('auth', token);
      res
        .status(http.StatusCodes.CREATED)
        .json({ message: 'User created successfully', user, token });
    } catch (err) {
      res
        .status(http.StatusCodes.INTERNAL_SERVER_ERROR)
        .json({ message: 'Error occurred' });
    }
  },

  async LoginUser(req, res) {
    try {
      if (!req.body.username || !req.body.password) {
        return res
          .status(http.StatusCodes.INTERNAL_SERVER_ERROR)
          .json({ message: 'No empty fields allowed' });
      }

      const user = await User.findOne({
        username: Helpers.firstUpper(req.body.username),
      });

      if (!user) {
        return res
          .status(http.StatusCodes.NOT_FOUND)
          .json({ message: 'Username not found' });
      }

      const result = await bcrypt.compare(req.body.password, user.password);
      if (!result) {
        return res
          .status(http.StatusCodes.INTERNAL_SERVER_ERROR)
          .json({ message: 'Password is incorrect' });
      }

      const token = jwt.sign({ data: user }, dbConfig.secret, {
        expiresIn: '5h',
      });

      res.cookie('auth', token);
      res
        .status(http.StatusCodes.OK)
        .json({ message: 'Login successful', user, token });
    } catch (err) {
      res
        .status(http.StatusCodes.INTERNAL_SERVER_ERROR)
        .json({ message: 'Error occurred' });
    }
  },
};
