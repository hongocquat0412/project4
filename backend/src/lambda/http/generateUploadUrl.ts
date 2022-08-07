import 'source-map-support/register'

import { APIGatewayProxyEvent, APIGatewayProxyResult, APIGatewayProxyHandler } from 'aws-lambda'
import { createLogger } from '../../utils/logger'
import { getUserId } from '../utils'
import { getUploadUrl, todoExists } from '../../businessLogicLayer/todos'

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  createLogger(`Processing upload image url corresponding to todo event: ${event}`)

  const userId = getUserId(event)
  const todoId = event.pathParameters.todoId
  const isValidTodo = await todoExists(todoId, userId)

  if (!isValidTodo) {
    return {
      statusCode: 404,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true
      },
      body: JSON.stringify({
        error: 'Todo item to which you are trying to upload image does not exist'
      })
    }
  }

  const imageUrl = await getUploadUrl(todoId, userId)

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
      uploadUrl: imageUrl
    })
  }
}

