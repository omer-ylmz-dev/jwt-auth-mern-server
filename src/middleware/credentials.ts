import {RequestHandler} from "express"



const credentials: RequestHandler = (req, res, next) => {
    if (req.headers.origin === process.env.CLIENT_URL as string) {
        res.header('Access-Control-Allow-Credentials', true as any);
    }
    next();
}

export default credentials