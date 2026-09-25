import {
  buildChallengeMessage,
  verifyChallengeSignature,
  verifyChallengeToken,
} from "../../src/lib/auth/challenge";
import {
  decryptPromptCiphertext,
  hashPromptPlaintext,
  normalizeContentHash,
  unwrapPromptKey,
} from "../../src/lib/crypto/promptCrypto";
import { fetchFromBlobStorage, isBlobReference } from "../../src/lib/stellar/blobStorage";
import {
  getPrompt,
  getPromptEncryptionVersion,
  getPurchaseDetails,
  hasAccess,
  type PromptHashConfig,
} from "../../src/lib/stellar/promptHashClient";
import { withObservability } from "../../src/lib/observability/wrapper";
import { withBodySizeLimit } from "../../src/lib/api/bodySizeLimit";
import { checkRateLimit } from "../../src/lib/observability/rateLimiter";
import {
  isAccountLocked,
  isCaptchaRequired,
  recordFailedAuthAttempt,
  recordSuccessfulAuth,
  verifyCaptchaToken,
} from "../../src/lib/auth/abuseProtection";
import { checkReplayProtection } from "../../src/lib/observability/replayProtection";
import { metrics } from "../../src/lib/observability/metrics";
import { dispatchEvent } from "../../server/src/services/webhookDispatcher";
import { recordAuditEvent } from "../../server/src/services/auditTrail";
import { apiError, ErrorCode } from "../../src/lib/api/errorCodes";
import { validateUnlockSecrets } from "../../src/lib/validation/envValidator";
import { negotiateVersion } from "../../src/lib/api/versionGuard";
import { withVersion } from "../../src/lib/api/payloadVersion";
import {
  parseRequestBody,
  UnlockRequestBody,
} from "../../src/lib/api/requestSchemas";

// Fail-fast module load validation
try {
  validateUnlockSecrets();
} catch (err: any) {
  console.error(err.message);
}


/**
 * Get active secrets for token verification
 * Supports multiple secrets during rotation grace period
 */
function getActiveSecrets(primarySecret: string): string[] {
  const secrets = [primarySecret];
  
  // Check for previous secret within grace period
  const previousSecret = process.env.CHALLENGE_TOKEN_SECRET_PREVIOUS;
  const rotationTimestamp = parseInt(
    process.env.CHALLENGE_TOKEN_ROTATION_TIMESTAMP || "0",
    10
  );
  const gracePeriodMs = parseInt(
    process.env.CHALLENGE_TOKEN_GRACE_PERIOD_MS || "300000", // 5 minutes default
    10
  );
  
  if (previousSecret && rotationTimestamp) {
    const timeSinceRotation = Date.now() - rotationTimestamp;
    if (timeSinceRotation < gracePeriodMs) {
      secrets.push(previousSecret);
    }
  }
  
  return secrets;
}

function getServerConfig(): PromptHashConfig {
  const rpcUrl =
    process.env.PUBLIC_STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
  const networkPassphrase =
    process.env.PUBLIC_STELLAR_NETWORK_PASSPHRASE ??
    "Test SDF Network ; September 2015";
  const promptHashContractId = process.env.PUBLIC_PROMPT_HASH_CONTRACT_ID ?? "";
  const nativeAssetContractId =
    process.env.PUBLIC_STELLAR_NATIVE_ASSET_CONTRACT_ID ??
    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
  const simulationAccount =
    process.env.PUBLIC_STELLAR_SIMULATION_ACCOUNT ?? process.env.UNLOCK_PUBLIC_KEY ?? "";

  return {
    rpcUrl,
    networkPassphrase,
    promptHashContractId,
    nativeAssetContractId,
    simulationAccount,
    allowHttp: new URL(rpcUrl).hostname === "localhost",
  };
}

async function handler(req: any, res: any) {
  try {
    validateUnlockSecrets();
  } catch (err: any) {
    req.logger.error("Configuration validation failed", { error: err.message });
    res.status(500).json(apiError(ErrorCode.CONFIGURATION_ERROR, "Configuration error."));
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json(apiError(ErrorCode.METHOD_NOT_ALLOWED, "Method not allowed."));
    return;
  }

  const version = negotiateVersion(req, res);
  if (!version) return;

  const parsed = parseRequestBody(UnlockRequestBody, req.body);
  if (!parsed.success) {
    res.status(400).json(
      apiError(
        ErrorCode.MISSING_FIELDS,
        "token, promptId, address, and signedMessage are required.",
        undefined,
        version,
      ),
    );
    return;
  }

  const unlockRequest = parsed.data;
  const clientIp = (req.headers["x-forwarded-for"] || req.socket.remoteAddress) as string;
  const address = unlockRequest.address;
  const promptId = unlockRequest.promptId;

  // Authenticated bucket: wallet address is present.
  const isAuthenticated = Boolean(address);

  // Rate limit by IP (unauthenticated bucket — strictest guard).
  const ipRateLimit = await checkRateLimit("unlock", clientIp, false);
  if (!ipRateLimit.success) {
    req.logger.warn({ clientIp }, "Rate limit exceeded for unlock (IP)");
    metrics.trackRateLimitHit("unlock_ip", clientIp);
    void recordAuditEvent({
      action: "unlock_rate_limited",
      result: "blocked",
      promptId: promptId ? String(promptId) : null,
      walletAddress: address ? String(address) : null,
      requestId: req.requestId ?? null,
      clientIp,
      reason: "ip_rate_limit_exceeded",
    });
    res.setHeader("X-RateLimit-Limit", ipRateLimit.limit);
    res.setHeader("X-RateLimit-Remaining", 0);
    res.setHeader("X-RateLimit-Reset", ipRateLimit.reset);
    res.status(429).json(
      apiError(ErrorCode.RATE_LIMIT_IP, "Too many requests. Please try again later.", {
        reset: ipRateLimit.reset,
      }, version),
    );
    return;
  }

  // Check if wallet account is locked after repeated auth failures
  if (address && typeof address === "string") {
    const lockStatus = await isAccountLocked(address);
    if (lockStatus.locked) {
      req.logger.warn({ address }, "Unlock requested for locked account");
      void recordAuditEvent({
        action: "unlock_account_locked",
        result: "blocked",
        promptId: promptId ? String(promptId) : null,
        walletAddress: String(address),
        requestId: req.requestId ?? null,
        clientIp,
        reason: "account_locked",
      });
      res.status(423).json(
        apiError(
          ErrorCode.ACCOUNT_LOCKED,
          "Account is locked due to too many failed authentication attempts.",
          { lockedUntil: lockStatus.lockedUntil },
          version,
        ),
      );
      return;
    }
  }

  // Rate limit by wallet address (authenticated bucket — per-wallet brute-force guard).
  if (address) {
    const walletRateLimit = await checkRateLimit("unlock", String(address), isAuthenticated);
    if (!walletRateLimit.success) {
      req.logger.warn({ address }, "Rate limit exceeded for unlock (Wallet)");
      metrics.trackRateLimitHit("unlock_wallet", String(address));
      void recordAuditEvent({
        action: "unlock_rate_limited",
        result: "blocked",
        promptId: promptId ? String(promptId) : null,
        walletAddress: String(address),
        requestId: req.requestId ?? null,
        clientIp,
        reason: "wallet_rate_limit_exceeded",
      });
      res.setHeader("X-RateLimit-Limit", walletRateLimit.limit);
      res.setHeader("X-RateLimit-Remaining", 0);
      res.setHeader("X-RateLimit-Reset", walletRateLimit.reset);
      res.status(429).json(
        apiError(ErrorCode.RATE_LIMIT_WALLET, "Too many unlock attempts for this wallet.", {
          reset: walletRateLimit.reset,
        }, version),
      );
      return;
    }
  }

  // Check if CAPTCHA is required due to repeated failures
  const addressStr = typeof address === "string" ? address : undefined;
  const captchaNeeded = await isCaptchaRequired(addressStr, clientIp);
  if (captchaNeeded) {
    const captchaToken =
      unlockRequest.captchaToken ||
      req.headers["x-captcha-token"];

    if (!captchaToken || typeof captchaToken !== "string") {
      req.logger.warn({ address: addressStr, clientIp }, "CAPTCHA required for unlock request");
      void recordAuditEvent({
        action: "unlock_captcha_required",
        result: "blocked",
        promptId: promptId ? String(promptId) : null,
        walletAddress: addressStr ?? null,
        requestId: req.requestId ?? null,
        clientIp,
        reason: "captcha_required",
      });
      res.status(403).json(
        apiError(
          ErrorCode.CAPTCHA_REQUIRED,
          "CAPTCHA verification is required to proceed.",
          { captchaRequired: true },
          version,
        ),
      );
      return;
    }

    const captchaResult = await verifyCaptchaToken(captchaToken, clientIp);
    if (!captchaResult.valid) {
      req.logger.warn(
        { address: addressStr, clientIp, reason: captchaResult.reason },
        "Invalid CAPTCHA token for unlock",
      );
      void recordAuditEvent({
        action: "unlock_captcha_failed",
        result: "blocked",
        promptId: promptId ? String(promptId) : null,
        walletAddress: addressStr ?? null,
        requestId: req.requestId ?? null,
        clientIp,
        reason: captchaResult.reason ?? "invalid_captcha",
      });
      res.status(403).json(
        apiError(
          ErrorCode.CAPTCHA_INVALID,
          "Invalid or expired CAPTCHA verification.",
          { captchaRequired: true },
          version,
        ),
      );
      return;
    }
  }

  const challengeSecret = process.env.CHALLENGE_TOKEN_SECRET;
  const unlockPublicKey = process.env.UNLOCK_PUBLIC_KEY;
  const unlockPrivateKey = process.env.UNLOCK_PRIVATE_KEY;

  if (!challengeSecret || !unlockPublicKey || !unlockPrivateKey) {
    req.logger.error("Unlock service is missing configuration secrets.");
    res.status(500).json(apiError(ErrorCode.CONFIGURATION_ERROR, "Configuration error.", undefined, version));
    return;
  }

  try {
    // Support multiple active secrets during rotation grace period
    const activeSecrets = getActiveSecrets(challengeSecret);
    
    const payload = verifyChallengeToken(
      activeSecrets,
      unlockRequest.token,
      unlockRequest.address,
      unlockRequest.promptId,
    );
    const challengeMessage = buildChallengeMessage(payload);
    const validSignature = verifyChallengeSignature(
      unlockRequest.address,
      challengeMessage,
      unlockRequest.signedMessage,
    );

    if (!validSignature) {
      req.logger.warn({ address: unlockRequest.address, promptId: unlockRequest.promptId }, "Invalid wallet signature");
      metrics.trackUnlockFailure(unlockRequest.address, unlockRequest.promptId, "invalid_signature");
      
      const failureStatus = await recordFailedAuthAttempt(unlockRequest.address, clientIp);

      if (failureStatus.locked) {
        req.logger.warn({ address: unlockRequest.address }, "Account locked after 5 failed auth attempts");
        void recordAuditEvent({
          action: "account_locked",
          result: "blocked",
          promptId: unlockRequest.promptId,
          walletAddress: unlockRequest.address,
          requestId: req.requestId ?? null,
          clientIp,
          reason: "max_failed_auth_attempts_exceeded",
        });
        res.status(423).json(
          apiError(
            ErrorCode.ACCOUNT_LOCKED,
            "Account is locked due to too many failed authentication attempts.",
            { lockedUntil: failureStatus.lockedUntil },
            version,
          ),
        );
        return;
      }

      void recordAuditEvent({
        action: "unlock_invalid_signature",
        result: "failure",
        promptId: unlockRequest.promptId,
        walletAddress: unlockRequest.address,
        requestId: req.requestId ?? null,
        clientIp,
        reason: "invalid_signature",
      });
      res.status(401).json(apiError(ErrorCode.INVALID_SIGNATURE, "Invalid wallet signature.", undefined, version));
      return;
    }

    const replayCheck = await checkReplayProtection(
      unlockRequest.token,
      unlockRequest.signedMessage,
    );
    if (!replayCheck.valid) {
      req.logger.warn(
        { address: unlockRequest.address, promptId: unlockRequest.promptId },
        "Replay attack detected",
      );
      metrics.trackUnlockFailure(
        unlockRequest.address,
        unlockRequest.promptId,
        "replay_detected",
      );
      void recordAuditEvent({
        action: "unlock_replay_detected",
        result: "blocked",
        promptId: unlockRequest.promptId,
        walletAddress: unlockRequest.address,
        requestId: req.requestId ?? null,
        clientIp,
        reason: "replay_attack",
      });
      res.status(400).json(
        apiError(ErrorCode.TEMPORARY_FAILURE, "This unlock request has already been processed.", undefined, version),
      );
      return;
    }

    const config = getServerConfig();
    const id = BigInt(unlockRequest.promptId);
    const access = await hasAccess(config, unlockRequest.address, id);
    if (!access) {
      req.logger.warn(
        { address: unlockRequest.address, promptId: unlockRequest.promptId },
        "Prompt access denied",
      );
      metrics.trackUnlockFailure(
        unlockRequest.address,
        unlockRequest.promptId,
        "no_access",
      );
      void recordAuditEvent({
        action: "unlock_no_access",
        result: "failure",
        promptId: unlockRequest.promptId,
        walletAddress: unlockRequest.address,
        requestId: req.requestId ?? null,
        clientIp,
        reason: "no_access",
      });
      res.status(403).json(
        apiError(ErrorCode.ACCESS_NOT_PURCHASED, "Prompt access has not been purchased.", undefined, version),
      );
      return;
    }

    const prompt = await getPrompt(config, id);

    // Determine the correct encryption version for this buyer.
    // If the caller is the creator they always get the current version;
    // otherwise we resolve the version that was locked in at purchase time.
    const currentVersion = prompt.encryptionVersion ?? 1;
    let targetVersion = currentVersion;
    if (prompt.creator?.toLowerCase() !== String(address).toLowerCase()) {
      const purchase = await getPurchaseDetails(config, id, String(address));
      // If no purchase record exists (legacy buyer), fall back to current version.
      targetVersion = purchase?.encryptionVersion ?? currentVersion;
    }

    // Fetch the encrypted payload for the resolved version.
    let encryptedPayload: {
      encryptedPrompt: string;
      encryptionIv: string;
      wrappedKey: string;
      contentHash: string;
    };
    if (targetVersion === currentVersion) {
      // Current version – use the prompt's live fields.
      encryptedPayload = {
        encryptedPrompt: prompt.encryptedPrompt!,
        encryptionIv: prompt.encryptionIv!,
        wrappedKey: prompt.wrappedKey!,
        contentHash: prompt.contentHash,
      };
    } else {
      // Archived version – fetch from versioned storage.
      const archived = await getPromptEncryptionVersion(
        config,
        id,
        targetVersion,
      );
      encryptedPayload = {
        encryptedPrompt: archived.encryptedPrompt,
        encryptionIv: archived.encryptionIv,
        wrappedKey: archived.wrappedKey,
        contentHash: archived.contentHash,
      };
    }

    if (isBlobReference(encryptedPayload.encryptedPrompt)) {
      try {
        encryptedPayload.encryptedPrompt = await fetchFromBlobStorage(encryptedPayload.encryptedPrompt);
      } catch (error) {
        req.logger.error(
          { address: unlockRequest.address, promptId: unlockRequest.promptId, error: error instanceof Error ? error.message : String(error) },
          "Failed to fetch encrypted prompt from blob storage"
        );
        res.status(502).json(
          apiError(ErrorCode.TEMPORARY_FAILURE, "Failed to fetch prompt data from blob storage.", undefined, version),
        );
        return;
      }
    }

    const keyBytes = await unwrapPromptKey(
      encryptedPayload.wrappedKey,
      unlockPublicKey,
      unlockPrivateKey,
    );
    const plaintext = await decryptPromptCiphertext(
      encryptedPayload.encryptedPrompt,
      encryptedPayload.encryptionIv,
      keyBytes,
    );
    const contentHash = await hashPromptPlaintext(plaintext);
    const storedHash = encryptedPayload.contentHash
      ? normalizeContentHash(encryptedPayload.contentHash)
      : "";

    // Determine integrity state exposed to the buyer
    const integrity = {
      status: ((): "verified" | "failed" | "unavailable" => {
        if (!encryptedPayload.contentHash) return "unavailable";
        if (contentHash !== storedHash) return "failed";
        return "verified";
      })(),
      computedHash: contentHash,
      storedHash: encryptedPayload.contentHash ?? null,
    };

    if (integrity.status === "failed") {
      req.logger.error(
        { address: unlockRequest.address, promptId: unlockRequest.promptId },
        "Prompt integrity check failed",
      );
      metrics.trackUnlockFailure(unlockRequest.address, unlockRequest.promptId, "integrity_failure");
      void recordAuditEvent({
        action: "unlock_integrity_failure",
        result: "failure",
        promptId: unlockRequest.promptId,
        walletAddress: unlockRequest.address,
        requestId: req.requestId ?? null,
        clientIp,
        reason: "integrity_failure",
      });
      void Promise.resolve(
        dispatchEvent(prompt.creator ?? "", "PromptIntegrityViolation", {
          promptId: prompt.id.toString(),
          buyer: String(unlockRequest.address),
          computedHash: integrity.computedHash,
          storedHash: integrity.storedHash,
        }),
      ).catch(() => {});

      res.status(200).json(
        withVersion(
          {
            promptId: prompt.id.toString(),
            title: prompt.title,
            contentHash,
            integrity,
          },
          version,
        ),
      );
      return;
    }

    await recordSuccessfulAuth(unlockRequest.address, clientIp);
    metrics.trackUnlockSuccess(unlockRequest.address, unlockRequest.promptId);
    req.logger.info(
      { address: unlockRequest.address, promptId: unlockRequest.promptId },
      "Prompt unlocked successfully",
    );
    void recordAuditEvent({
      action: "unlock_success",
      result: "success",
      promptId: unlockRequest.promptId,
      walletAddress: unlockRequest.address,
      requestId: req.requestId ?? null,
      clientIp,
      reason: null,
    });

    void Promise.resolve(
      dispatchEvent(prompt.creator ?? "", "PromptPurchased", {
        promptId: prompt.id.toString(),
        buyer: unlockRequest.address,
        title: prompt.title,
      }),
    ).catch(() => {});

    res.status(200).json(
      withVersion(
        {
          promptId: prompt.id.toString(),
          title: prompt.title,
          contentHash,
          plaintext,
          integrity,
        },
        version,
      ),
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to unlock prompt.";
    req.logger.error(
      {
        address: unlockRequest.address,
        promptId: unlockRequest.promptId,
        error: message,
      },
      "Unlock attempt failed",
    );
    metrics.trackUnlockFailure(unlockRequest.address, unlockRequest.promptId, "error");

    // Distinguish expired-challenge errors for finer-grained audit reasons and error codes.
    const isExpired = message.toLowerCase().includes("expired");
    void recordAuditEvent({
      action: isExpired ? "unlock_expired_challenge" : "unlock_error",
      result: "failure",
      promptId: unlockRequest.promptId,
      walletAddress: unlockRequest.address,
      requestId: req.requestId ?? null,
      clientIp,
      reason: isExpired ? "expired_challenge" : "error",
    });

    if (isExpired) {
      res.status(400).json(
        apiError(ErrorCode.CHALLENGE_EXPIRED, "The challenge token has expired. Please request a new one.", undefined, version),
      );
    } else {
      res.status(400).json(
        apiError(ErrorCode.TEMPORARY_FAILURE, "Failed to unlock prompt. Please try again.", undefined, version),
      );
    }
  }
}

export default withObservability(withBodySizeLimit(handler), "prompts/unlock");
