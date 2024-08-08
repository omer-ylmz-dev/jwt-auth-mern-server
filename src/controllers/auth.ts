import userSchema from "../models/user"
import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';







// ******************************************************************


export const login = async (req: Request, res: Response): Promise<any> => {
	try {
		const { username, password }: { username: string, password: string } = req.body;
		const user = await userSchema.findOne({ username });

		if (!user) {
			return res.status(401).json({ message: "Invalid username or password" });
		}

		const passComparing = await bcrypt.compare(password, user.password as string);

		if (!passComparing) {
			return res.status(401).json({ message: "Invalid username or password" });
		}

		const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_SESSION_SECRET as string, { expiresIn: "5m" });
		const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_SESSION_SECRET as string, { expiresIn: "30m" });

		res.cookie('session_refresh', refreshToken, { httpOnly: true, sameSite: 'none', secure: true, maxAge: 1800000 });
		res.cookie('session_access', accessToken, { httpOnly: true, sameSite: 'none', secure: true, maxAge: 300000 });

		res.status(200).json({ accessToken: accessToken });

	} catch (err: any) {
		return res.status(500).json({ message: err.message });
	}
}


// ******************************************************************



export const register = async(req: Request, res: Response): Promise<any> => {
	try {
		const { email, username, password }: { email: string, username: string, password: string } = req.body;

		const mailCheck = await userSchema.findOne({ email });
		const userCheck = await userSchema.findOne({ username });

		if (mailCheck) {
			return res.status(409).json({ message: "This mail address is already in use" });
		}
		if (!isEmailAddress(email)) {
			return res.status(400).json({ message: "This mail address is incorrect" });
		}
		if (userCheck) {
			return res.status(409).json({ message: "This username already exists" });
		}
		if (!username) {
			return res.status(400).json({ message: "Please choose a username" });
		}
		if (!isCorrectPassword(password)) {
			return res.status(400).json({ message: "Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, no space, and it must be 8-16 characters long" });
		}

		const passHash = await bcrypt.hash(password, 12);
		const user = await userSchema.create({ email, username, password: passHash });

		if (user) {
			const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_SESSION_SECRET as string, { expiresIn: "5m" });
			const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_SESSION_SECRET as string, { expiresIn: "30m" });

			res.cookie('session_refresh', refreshToken, { httpOnly: true, sameSite: 'none', secure: true, maxAge: 1800000 });
			res.cookie('session_access', accessToken, { httpOnly: true, sameSite: 'none', secure: true, maxAge: 300000 });

			res.status(200).json({ accessToken: accessToken });
		}

	} catch (err: any) {
		return res.status(500).json({ message: err.message });
	}
}



// ******************************************************************



export const logout = async (req: any, res: any): Promise<any> => {
	try {
		if (!req.cookies) {
			return res.status(500).json("There is some mistakes");
		}

		res.clearCookie('session_refresh', { httpOnly: true, sameSite: 'None', secure: true });
		res.clearCookie('session_access', { httpOnly: true, sameSite: 'None', secure: true });

		return res.status(200).json({ message: "User has Logged Out" });

	} catch (err: any) {
		return res.status(500).json({ message: err.message });
	}
}



// ******************************************************************


export const verifyRefreshToken = async(req: any, res: any): Promise<any> => {
	
		if(!req.cookies.session_access){
			jwt.verify(req.cookies.session_refresh, process.env.REFRESH_SESSION_SECRET as string, (err: any, decoded: any) => {
				if(err){
					return res.status(500).json("Your session is over!")
				}else{
					
					const newAccessToken: string = jwt.sign({username: decoded.username}, process.env.ACCESS_SESSION_SECRET as string, {expiresIn: "5m"}) 
					
					res.cookie('session_access', newAccessToken, { httpOnly: true, sameSite: 'none', secure: true, maxAge:300000 });
								
					return res.status(200).json({message:"Your New Token is: ", accessToken:newAccessToken})
					
				}
			})
			
		}else{
			return res.status(200).json({message:"Your Token is: ", accessToken:req.cookies.session_access})
			
		}
		
}



// ******************************************************************

export const deleteAccount = async(req: Request, res: Response): Promise<any> => {

	try{
		const user = await userSchema.findOne({username:req.params.username})	
	
		if(user){
			await userSchema.findOneAndDelete({username:req.params.username})
			res.clearCookie('session_refresh', { httpOnly: true, sameSite: 'none', secure: true });
			res.clearCookie('session_access', { httpOnly: true, sameSite: 'none', secure: true });
			return res.status(200).json({message:"Your account has been deleted"})
		}else{
			return res.status(500).json({message:"There is some mistakes.Try again"})
		}
	
	}catch(err:any){
		return res.status(500).json({message:err.message})
	}
}



// ******************************************************************






function isEmailAddress(mailAddress:string){
	let regex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
	
	if(mailAddress.match(regex)) return true
	else return false
}



function isCorrectPassword(checkPassword:string){
	let regex = /^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?!.* ).{8,16}$/;
	
	if(checkPassword.match(regex)) return true
	else return false
}