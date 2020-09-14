import express from 'express'
import {addBlacklistToken, findUserByEmail, getGraphQL, getRequestData, validateEmail} from '../utils'
import bcrypt from 'bcrypt'
import axios from 'axios'
import jwt from 'jsonwebtoken'
import {adminConfig} from '../config/adminConfig'

const cookieConfig = {
	httpOnly: true,
	// secure: true,
	maxAge: 10800000,
	signed: true
}

const register = async (req: express.Request, res: express.Response) => {
	const {
		email,
		password
	} = req.body

	if (email === '' || password === '') {
		res.json({
			status: 'error',
			message: 'Enter Email and Password'
		})
		return
	}

	const isEmailValid = validateEmail(email)

	if (!isEmailValid) {
		res.json({
			status: 'error',
			message: 'Invalid Email'
		})
		return
	}

	let userExists = null

	try {
		userExists = await findUserByEmail(email)

	} catch (err) {
		console.error(err)
		res.json({
			status: 'error',
			message: 'Server Error'
		})
		return
	}

	let registerUserResponse = null
	if (!userExists) {
		try {
			const registerUser = await getGraphQL('mutation', 'registerUser')

			const hashedPassword = await bcrypt.hash(password, 10)

			const data = getRequestData(registerUser, {
				email,
				password: hashedPassword
			})
			registerUserResponse = await axios.post('http://localhost:8080/v1/graphql', data, adminConfig)

		} catch (err) {
			console.error(err)
			res.json({
				status: 'error',
				message: 'Server Error'
			})
			return
		}
	} else {
		res.json({
			status: 'error',
			message: 'Please Login'
		})
		return
	}

	res.json(registerUserResponse.data)
}

const login = async (req: express.Request, res: express.Response) => {
	const {
		email,
		password
	} = req.body

	let userData = null

	try {
		userData = await findUserByEmail(email)

	} catch (err) {
		console.error(err)
	}

	if (!userData) {
		res.status(401).json({
			status: 'error',
			message: 'Invalid Email or Password'
		})
		return
	}

	const hashedPassword = userData.data.user[0].password

	const passwordsMatch = await bcrypt.compare(password, hashedPassword)

	if (!passwordsMatch) {
		res.status(401).json({
			status: 'error',
			message: 'Invalid Email or Password'
		})
		return
	}

	delete userData.data.user[0].password

	const accessTokenSecret = process.env.JWT_ACCESS_SECRET as string
	const refreshTokenSecret = process.env.JWT_REFRESH_SECRET as string

	const user = userData.data.user[0]

	const accessToken = jwt.sign({user}, accessTokenSecret, {
		expiresIn: '15m'
	})

	const refreshToken = jwt.sign({user}, refreshTokenSecret, {
		expiresIn: '30s'
	})

	res.cookie('refreshToken', refreshToken, cookieConfig)

	res.json({
		accessToken
	})
}

const refreshToken = async (req: express.Request, res: express.Response) => {
	const {refreshToken} = req.signedCookies

	// check if refresh token exists in request
	// return 401 if null
	if (refreshToken === null) {
		res.sendStatus(401)
		return
	}

	// check if blacklisted token db contains the refresh token
	let refreshTokenExists = false
	let getBlacklistedTokenResponse = null

	try {
		const getBlacklistedToken = await getGraphQL('query', 'getBlacklistedToken')

		const data = getRequestData(getBlacklistedToken, {
			token: refreshToken
		})
		getBlacklistedTokenResponse = await axios.post('http://localhost:8080/v1/graphql', data, adminConfig)

		if (getBlacklistedTokenResponse.data.data.blacklisted_tokens_by_pk !== null) {
			res.sendStatus(401)
			return
		}

	} catch (err) {
		console.error(err)
		res.sendStatus(502)
		return
	}

	// if it does, return 403
	if (refreshTokenExists) {
		res.sendStatus(403)
		return
	}

	// if it doesn't, verify with jwt.verify()
	const refreshTokenSecret = process.env.JWT_REFRESH_SECRET as string

	let decodedToken = null
	try {
		decodedToken = jwt.verify(refreshToken, refreshTokenSecret)
	} catch (err) {
		// if verification fails, return 403
		console.error(err)
		res.sendStatus(403)
		return
	}

	const accessTokenSecret = process.env.JWT_ACCESS_SECRET as string

	let newAccessToken = null
	let newRefreshToken = null
	// decoded successfully, generate new accessToken and refreshToken
	if (decodedToken) {
		// @ts-ignore
		const {user} = decodedToken
		newAccessToken = jwt.sign({user}, accessTokenSecret, {
			expiresIn: '15m'
		})

		newRefreshToken = jwt.sign({user}, refreshTokenSecret, {
			expiresIn: '3h'
		})
	}

	await addBlacklistToken(refreshToken, decodedToken, res)

	// send new accessToken and refreshToken to the client
	res.cookie('refreshToken', newRefreshToken, cookieConfig)

	res.json({
		accessToken: newAccessToken
	})
}

const logout = async (req: express.Request, res: express.Response) => {
	const {accessToken} = req.body
	const {refreshToken} = req.signedCookies

	// check if access and refresh token exists in request
	// return 401 if null
	if (refreshToken === null || accessToken === null) {
		res.sendStatus(401)
		return
	}

	// verify access token and add it to blacklist
	const accessTokenSecret = process.env.JWT_ACCESS_SECRET as string
	try {
		const decodedAccessToken = jwt.verify(accessToken, accessTokenSecret)
		await addBlacklistToken(accessToken, decodedAccessToken, res)

	} catch (err) {
		console.error(err)
		res.sendStatus(403)
		return
	}

	// verify refresh token and add it to blacklist
	const refreshTokenSecret = process.env.JWT_REFRESH_SECRET as string
	try {
		const decodedRefreshToken = jwt.verify(refreshToken, refreshTokenSecret)
		await addBlacklistToken(refreshToken, decodedRefreshToken, res)
	} catch (err) {
		console.error(err)
		res.sendStatus(403)
		return
	}

	// remove cookie from the client
	res.clearCookie('refreshToken')

	// redirect to homepage
	res.redirect('/')
}

export default {register, login, refreshToken, logout}

