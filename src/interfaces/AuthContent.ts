import {OutputUser} from './User';

interface AuthContent {
  token: string;
  userFromToken: OutputUser;
  updated?: boolean;
}

export {AuthContent};
