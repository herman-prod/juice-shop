/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

export function securityQuestion () {
  return async (_req: Request, res: Response, next: NextFunction) => {
    try {
      // Do not disclose whether an email exists or return a user-specific security question.
      // This prevents account enumeration and sensitive information disclosure via the email parameter.
      res.json({})
    } catch (error) {
      next(error)
    }
  }
}
