import type { Request, Response } from 'express';
export declare class AuthController {
    static createAccount: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static confirmAccount: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static login: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static requestConfirmationCode: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static forgotPassword: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static validateToken: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static updatePasswordWithToken: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static user: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static updateProfile: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static updateCurrentUserPassword: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
    static checkPassword: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
}
