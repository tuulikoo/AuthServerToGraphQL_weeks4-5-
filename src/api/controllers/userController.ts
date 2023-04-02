import {Request, Response, NextFunction} from 'express';
import CustomError from '../../classes/CustomError';
import bcrypt from 'bcryptjs';
import {OutputUser, User} from '../../interfaces/User';
import userModel from '../models/userModel';
import DBMessageResponse from '../../interfaces/DBMessageResponse';
import {validationResult} from 'express-validator';
import jwt from 'jsonwebtoken';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';

const salt = bcrypt.genSaltSync(12);

const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const users = await userModel.find().select('-password -role');
    res.json(users);
  } catch (error) {
    next(error);
  }
};

const userGet = async (
  req: Request<{id: string}, {}, {}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      console.log('cat_post validation', messages);
      next(new CustomError(messages, 400));
      return;
    }

    const user = await userModel
      .findById(req.params.id)
      .select('-password -role');
    if (user) {
      res.json(user);
    } else {
      throw new CustomError('User not found', 404);
    }
  } catch (error) {
    next(new CustomError((error as Error).message, 400));
  }
};

const userPost = async (
  req: Request<{}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    console.log('userPost', req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      console.log('cat_post validation', messages);
      next(new CustomError(messages, 400));
      return;
    }

    const user = req.body;
    user.role = 'user';
    user.password = bcrypt.hashSync(user.password!, salt);
    const newUser = await userModel.create(user);
    const outUser: OutputUser =  {
      user_name: newUser.user_name,
      email: newUser.email,
      id: newUser._id,
    }
    const token = jwt.sign(outUser, 'asdf');
    const response: LoginMessageResponse = {
      message: 'user created',
      token,
    };
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 400));
  }
};

const userPutCurrent = async (
  req: Request<{}, {}, {token: string}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      console.log('cat_post validation', messages);
      next(new CustomError(messages, 400));
      return;
    }

    const {token} = req.body;
    const user = jwt.verify(token, 'asdf') as OutputUser;
    const result = await userModel
      .findByIdAndUpdate(user.id, user, {
        new: true,
      })
      .select('-password -role');
    if (result) {
      const newToken = jwt.sign(result, 'asdf');
      const response: LoginMessageResponse = {
        message: 'user created',
        token: newToken,
      };
      res.json(response);
    }
  } catch (error) {
    next(new CustomError((error as Error).message, 400));
  }
};

const userDeleteCurrent = async (
  req: Request<{},{},{token: string}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      console.log('cat_post validation', messages);
      next(new CustomError(messages, 400));
      return;
    }

    const {token} = req.body;
    const user = jwt.verify(token, 'asdf') as OutputUser;

    const result = await userModel
      .findByIdAndDelete(user.id)
      .select('-password -role');
    if (result) {
      const newToken = jwt.sign(result, 'asdf');
      const response: LoginMessageResponse = {
        message: 'user deleted',
        token: newToken,
      };
      res.json(response);
    }
  } catch (error) {
    next(new CustomError((error as Error).message, 400));
  }
};

const checkToken = async (req: Request<{}, {}, {token: string}>, res: Response, next: NextFunction) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
      .array()
      .map((error) => `${error.msg}: ${error.param}`)
      .join(', ');
      console.log('cat_post validation', messages);
      next(new CustomError(messages, 400));
      return;
    }

    const {token} = req.body;
    const user = jwt.verify(token, 'asdf') as OutputUser;
    const result = await userModel.findById(user.id).select('-password');
    if (result) {
      const newToken = jwt.sign(result, 'asdf');
      const response: LoginMessageResponse = {
        message: 'valid token',
        token: newToken,
      };
      res.json(response);
      return;
    }
    next(new CustomError('token not valid', 403));
  } catch (error) {
    next(new CustomError((error as Error).message, 400));
  }

};

export {
  userListGet,
  userGet,
  userPost,
  userPutCurrent,
  userDeleteCurrent,
  checkToken,
};
