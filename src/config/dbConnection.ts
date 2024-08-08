import mongoose from "mongoose";


const dbConnection = async () => {
	try {
		const connection = await mongoose.connect(process.env.MONGO_URI as string);
		console.log("MongoDB CONNECTED !");
	} catch (err) {
		console.error(err);
		process.exit(1);
	}
};


export default dbConnection