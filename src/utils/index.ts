import {loadDocuments} from '@graphql-tools/load'
import {GraphQLFileLoader} from '@graphql-tools/graphql-file-loader'
import axios from 'axios'
import {adminConfig} from '../config/adminConfig'

type validateEmailType = (email: string) => boolean
type getRequestDataType = (query: string | undefined, variables: {[k: string]: string}) => string
type getGraphQLType = (operation: 'query' | 'mutation',fileName: string) => Promise<string | undefined>
type findUserByEmailType = (email: string) => Promise<{ [k: string]: any } | null>

export const validateEmail: validateEmailType = (email) => {
	const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
	return re.test(String(email).toLowerCase())
}

export const getRequestData: getRequestDataType = (query, variables) => {
	return JSON.stringify({
		query,
		variables
	})
}

export const getGraphQL: getGraphQLType = async (operation, fileName) => {

	const operationType = operation === 'query' ? 'queries' : 'mutations'

	const document = await loadDocuments(`src/graphql/${operationType}/${fileName}.graphql`, {
		loaders: [
			new GraphQLFileLoader()
		]
	})
	return document[0].rawSDL
}

export const findUserByEmail: findUserByEmailType = async email => {
	let findUserResponse = null

	const getUserByEmail = await getGraphQL('query', 'getUserByEmail')

	const data = getRequestData(getUserByEmail, {
		email
	})

	findUserResponse = await axios.post('http://localhost:8080/v1/graphql', data, adminConfig)

	if (findUserResponse !== null && findUserResponse.data.data.user.length !== 0) {
		return findUserResponse.data
	} else {
		return null
	}
}
