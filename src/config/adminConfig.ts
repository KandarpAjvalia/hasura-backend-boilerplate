import dotenv from 'dotenv'

dotenv.config()

export const adminConfig = {
	headers: {
		'x-hasura-admin-secret': process.env.HASURA_ADMIN_SECRET,
		'Content-Type': 'application/json'
	},
}
