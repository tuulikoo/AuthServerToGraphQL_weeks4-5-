import {Request, Response, NextFunction} from 'express';
import CustomError from '../../classes/CustomError';
import bcrypt from 'bcryptjs';
import {OutputUser, User} from '../../interfaces/User';
import userModel from '../models/userModel';
import {validationResult} from 'express-validator';
import jwt from 'jsonwebtoken';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';
import MessageResponse from '../../interfaces/MessageResponse';

const salt = bcrypt.genSaltSync(12);

const check = (req: Request, res: Response) => {
  console.log('check');
  res.json({message: 'I am alive'});
};

const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    console.log('userListGet');
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
    console.log('userGet', req.params.id);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
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
      next(new CustomError(messages, 400));
      return;
    }

    const user = req.body;
    user.role = 'user';
    user.password = bcrypt.hashSync(user.password!, salt);
    const newUser = await userModel.create(user);
    const response: MessageResponse = {
      message: `User ${newUser.user_name} created`,
    };
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 400));
  }
};

const userPutCurrent = async (
  req: Request<{}, {}, User>,
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
      next(new CustomError(messages, 400));
      return;
    }

    const authUser = res.locals.user;
    const result = await userModel
      .findByIdAndUpdate(authUser.id, req.body, {
        new: true,
      })
      .select('-password -role');
    if (result) {
      const newUser: OutputUser = {
        id: result._id,
        user_name: result.user_name,
        email: result.email,
      };
      const newToken = jwt.sign(newUser, process.env.JWT_SECRET as string);
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
  req: Request,
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
      next(new CustomError(messages, 400));
      return;
    }

    const {user} = res.locals;

    const result = await userModel
      .findByIdAndDelete(user.id)
      .select('-password -role');
    if (result) {
      const newUser: OutputUser = {
        id: result._id,
        user_name: result.user_name,
        email: result.email,
      };
      const newToken = jwt.sign(newUser, process.env.JWT_SECRET as string);
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

const checkToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const messages: string = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      next(new CustomError(messages, 400));
      return;
    }

    const {user} = res.locals;
    const result = await userModel.findById(user.id).select('-password -role');
    if (result) {
      const newUser: OutputUser = {
        id: result._id,
        user_name: result.user_name,
        email: result.email,
      };
      const newToken = jwt.sign(newUser, process.env.JWT_SECRET as string);
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
  check,
  userListGet,
  userGet,
  userPost,
  userPutCurrent,
  userDeleteCurrent,
  checkToken,
};
