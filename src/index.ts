import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import authRouter from "./routes/auth";

import dbConnection from "./config/dbConnection";
import credentials from "./middleware/credentials";
import verifyToken from "./middleware/verifyToken";

const app = express();


dbConnection();

app.use(credentials);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(cors({
	origin:process.env.CLIENT_URL as string,
	credentials:true
}))

app.use(cookieParser());


app.use(verifyToken)
app.use("/auth",authRouter);


app.listen(process.env.PORT,() => {
	console.log(`Server is running on ${process.env.PORT}`)
})