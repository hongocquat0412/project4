import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

const authCert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJd9D5CWBQ38N5MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi1odDdzYW9yYy51cy5hdXRoMC5jb20wHhcNMjIwODA3MTQyMjE0WhcN
MzYwNDE1MTQyMjE0WjAkMSIwIAYDVQQDExlkZXYtaHQ3c2FvcmMudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0c3eVB1eaIWQLGD0
ZZwzs6qSAUSaSKDQdQrr4r361DCPqaXev/Dc+ipujefdC1e9yju7sR6tMZiys9bd
9gmOQj7P27XEWqGeifnDs4TM/RJd1Vvd/pSzledNWwZdsTMl1c1orQeBoTE6eVcD
CxmeAgFKnq98m09Bh893N+7iHt8WVrIiRDEK+odirjxFtK9tPcHIchARYTRkaFyz
mb9AhWyKbnrI0XOFw5xLDylwCSgXMvV+vqC+zrMpLRYWfiE+WhBacbvP8UqMUcgl
uMOn65K1ZrfP7YkiQPMUMDb8+13pPBgUx9Y1qBBdkzTWi37EAGqVmBogoTbz1V4K
ET8ZRQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRl47nIPMKL
yf2poETCRlqArFG8lTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AMTNxXo9GIgQVDkx7SyNJ2eDHPnrift+bmY3QzD6wgu4znyX2mCTFxhfrRoBvxJl
BTjFiYW21HjYKUSG+5WjWeqnS9nCl1PGdcxB9dok901TfKuxAHBqcz2+aFisjz6G
rf/g0uwKFkzfG2SCpBAFUU0938HQ0wW3F/vKDnD8cIonQPxP/sU6j2mZJw/kV9xR
qByBIyJrcwF2wcFAT1fTftwX9XT8tGb5NfgInH4zJTxyXSGonGFxYRNsqiasZfcf
hj15sW4/bnjV20uaOhyKQdOEYTQ8Hrew7rmzUFTlftn3OJLCA7oNxJx88qjwO4GH
Xx6RPcq0qgMZxEfbat1qQeM=
-----END CERTIFICATE-----
`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)  
  return verify(token, authCert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')
  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')
  const split = authHeader.split(' ')
  const token = split[1]
  return token
}
