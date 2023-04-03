import {OutputUser} from './User';

export default interface LoginMessageResponse {
  message: string;
  updated?: boolean;
  token?: string;
  user?: OutputUser;
}
