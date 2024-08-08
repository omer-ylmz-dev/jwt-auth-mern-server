import {Request,Response,NextFunction} from "express"
import jwt from "jsonwebtoken";



const verifyToken = (req: Request, res: Response, next: NextFunction): any => {
    const authHeader: string | any = req.headers.authorization || req.headers.Authorization;
	if(authHeader){
		const token: string = authHeader.split(' ')[1];
		console.log("Bearer token: ", token);
	}
	next()
};

export default verifyToken