import * as AWS  from 'aws-sdk'
import { DocumentClient } from 'aws-sdk/clients/dynamodb'

import { TodoItem } from '../models/TodoItem'
import { UpdateTodoRequest } from '../requests/UpdateTodoRequest'
import { createLogger } from '../utils/logger'

export class Todo {

  constructor(
    private readonly docClient: DocumentClient = createDynamoDBClient(),
    private readonly todosTable = process.env.TODOS_TABLE) {
  }

  async getAllTodos(userId: string): Promise<TodoItem[]> {    

    const parameters = {
      TableName: this.todosTable,
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: {
        ':userId': userId
      },
      ScanIndexForward: false
    }

    const result = await this.docClient.query(parameters).promise()

    return result.Items as TodoItem[]
  }

  async createTodo(todoItem: TodoItem): Promise<TodoItem> {
    await this.docClient.put({
      TableName: this.todosTable,
      Item: todoItem
    }).promise()

    return todoItem;
  }

  async updateTodo(todoId: string, userId: string, updatedTodo: UpdateTodoRequest): Promise<void> {
    await this.docClient.update({
      TableName: this.todosTable,
      Key: {
        todoId,
        userId
      },
      ExpressionAttributeNames: {
        '#N': 'name'
      },
      UpdateExpression: 'SET #N = :name, dueDate = :dueDate, done = :done',
      ExpressionAttributeValues: {
        ':name': updatedTodo.name,
        ':dueDate': updatedTodo.dueDate,
        ':done': updatedTodo.done
      }
    }).promise()
  }

  async updateTodoAttachment(todoId: string, userId: string, imageUrl: string): Promise<void> {
    await this.docClient.update({
      TableName: this.todosTable,
      Key: {
        todoId,
        userId
      },
      UpdateExpression: 'SET attachmentUrl = :attachment',
      ExpressionAttributeValues: {
        ':attachment': imageUrl
      }
    }).promise()
  }

  async deleteTodo(todoId: string, userId: string): Promise<void> {
    try {
      await this.docClient.delete({
        TableName: this.todosTable,
        Key: {
          todoId,
          userId
        }
      }).promise()
    } catch(err) {
      createLogger(`Error while deleting ToDo: ${err}`)
    }
  }

  async getTodo(todoId: string, userId: string) {
    const output = await this.docClient
      .get({
        TableName: this.todosTable,
        Key: {
          todoId,
          userId
        }
      })
      .promise()

    return output.Item
  }
}

function createDynamoDBClient() {
  return new AWS.DynamoDB.DocumentClient()
}
