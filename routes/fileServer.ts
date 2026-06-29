/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
const FTP_BASE_DIR = path.resolve('ftp')
const SAFE_FILE_NAME = /^[a-zA-Z0-9_.-]+$/

export function servePublicFiles() {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
  /*
  function verify (file: string, res: Response, next: NextFunction) {
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      file = security.cutOffPoisonNullByte(file)

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }*/
  function verify(file: string, res: Response, next: NextFunction) {
    const requestedFile = security.cutOffPoisonNullByte(file)

    if (
      !requestedFile ||
      !SAFE_FILE_NAME.test(requestedFile) ||
      !(endsWithAllowlistedFileType(requestedFile) || requestedFile === 'incident-support.kdbx')
    ) {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
      return
    }

    const targetPath = path.resolve(FTP_BASE_DIR, requestedFile)
    const relativePath = path.relative(FTP_BASE_DIR, targetPath)

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      res.status(403)
      next(new Error('Invalid file path'))
      return
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => {
      return requestedFile.toLowerCase() === 'acquisitions.md'
    })

    verifySuccessfulPoisonNullByteExploit(requestedFile)

    res.sendFile(targetPath)
  }
  function verifySuccessfulPoisonNullByteExploit(file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType(param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
