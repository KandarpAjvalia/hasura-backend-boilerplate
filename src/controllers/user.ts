import express from 'express'
import {findUserByEmail, getGraphQL, getRequestData, validateEmail} from '../utils'
import bcrypt from 'bcrypt'
import axios from 'axios'
import jwt from 'jsonwebtoken'
import {adminConfig} from '../config/adminConfig'
import dotenv from 'dotenv'

dotenv.config()

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
		res.json({
			status: 'error',
			message: 'Invalid Email or Password'
		})
		return
	}

	const hashedPassword = userData.data.user[0].password

	const passwordsMatch = await bcrypt.compare(password, hashedPassword)

	if (!passwordsMatch) {
		res.json({
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
		expiresIn: '3h'
	})

	res.json({
		accessToken,
		refreshToken
	})
}

const refreshToken = async (req: express.Request, res: express.Response) => {
	const { refreshToken } = req.body

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
			token: refreshToken,
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

	// add old refresh token to blacklisted
	let addBlacklistTokenResponse = null
	try {
		const addBlacklistToken = await getGraphQL('mutation', 'addBlacklistToken')

		// @ts-ignore
		const refreshTokenExp = decodedToken.exp

		const data = getRequestData(addBlacklistToken, {
			token: refreshToken,
			exp: new Date(refreshTokenExp * 1000).toISOString()
		})
		addBlacklistTokenResponse = await axios.post('http://localhost:8080/v1/graphql', data, adminConfig)

	} catch (err) {
		console.error(err)
		res.sendStatus(502)
	}

	// send new accessToken and refreshToken to the client

	res.json({
		accessToken: newAccessToken,
		refreshToken: newRefreshToken
	})
}

export default {register, login, refreshToken}

