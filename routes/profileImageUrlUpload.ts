/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  // IPv6 loopback / unique-local (fc00::/7)
  if (ip === '::1' || ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true
  // IPv4 private ranges
  if (ip.startsWith('10.')) return true
  if (ip.startsWith('127.')) return true
  if (ip.startsWith('169.254.')) return true // link-local
  if (ip.startsWith('172.')) {
    const secondOctet = Number(ip.split('.')[1])
    if (secondOctet >= 16 && secondOctet <= 31) return true
  }
  if (ip.startsWith('192.168.')) return true
  return false
}

async function assertSafeHttpUrl (url: string): Promise<string> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new Error('Invalid URL')
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only http/https URLs are allowed')
  }

  // Block explicit localhost-style hostnames immediately
  const hostname = parsed.hostname
  if (!hostname || hostname.length === 0) throw new Error('Invalid hostname')
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '0.0.0.0' ||
    hostname === '::'
  ) {
    throw new Error('Local addresses are not allowed')
  }

  // Resolve and ensure all A/AAAA targets are not private/internal.
  // (Blocks many SSRF and DNS rebinding attempts by checking resolved IPs.)
  const lookupOptions = dns.promises ? dns.promises : (dns as any)
  const results = await lookupOptions.lookup(hostname, { all: true })

  const ips = Array.isArray(results)
    ? results.map((r: any) => r.address).filter(Boolean)
    : (results?.address ? [results.address] : [])

  if (ips.length === 0) throw new Error('Unable to resolve hostname')

  for (const ip of ips) {
    // Reject malformed IPs
    if (!net.isIP(ip)) throw new Error('Invalid resolved IP')
    if (isPrivateIp(ip)) throw new Error('Private/internal IP addresses are not allowed')
  }

  return parsed.toString()
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const safeUrl = await assertSafeHttpUrl(String(url))

          const response = await fetch(safeUrl)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }

          const contentType = response.headers.get('content-type') || ''
          if (!contentType.toLowerCase().startsWith('image/')) {
            throw new Error('URL did not return an image content-type')
          }

          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(String(safeUrl).split('.').slice(-1)[0].toLowerCase()) ? String(safeUrl).split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
