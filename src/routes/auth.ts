import {Router} from "express"
const router = Router()

import {
	login,
	register,
	logout,
	verifyRefreshToken,
	deleteAccount
} from "../controllers/auth"


router.post("/login",login)
router.post("/register",register)
router.post("/logout",logout)
router.get("/verify-refresh-token",verifyRefreshToken)
router.post("/delete-account/:username",deleteAccount)


export default router